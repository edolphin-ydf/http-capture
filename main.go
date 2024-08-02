package main

import (
	"bytes"
	"compress/gzip"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/bytedance/sonic"
	"github.com/yuin/gopher-lua"
	"gopkg.in/yaml.v3"
)

type CaptureField struct {
	Field    string `yaml:"Field"`
	MapKey   string `yaml:"MapKey"`
	MapValue string `yaml:"MapValue"`
}

func (cf *CaptureField) mapValue(value string) string {
	if cf.MapValue == "" {
		return value
	}

	L := lua.NewState()
	defer L.Close()
	L.SetGlobal("value", lua.LString(value))
	if err := L.DoString(cf.MapValue); err != nil {
		panic(err)
	}
	return L.Get(-1).String()
}

type CaptureDefine struct {
	Host     string         `yaml:"Host"`
	Path     string         `yaml:"Path"`
	Operator string         `yaml:"Operator"`
	Method   string         `yaml:"Method"`
	Source   string         `yaml:"Source"`
	Capture  []CaptureField `yaml:"Capture"`
}

func (c *CaptureDefine) isPathMatch(session *gomitmproxy.Session) bool {
	switch c.Operator {
	case OperatorEqual:
		return session.Request().URL.Path == c.Path
	case OperatorContains:
		return strings.Contains(session.Request().URL.Path, c.Path)
	default:
		return false
	}
}

func (c *CaptureDefine) isMethodMatch(session *gomitmproxy.Session) bool {
	return session.Request().Method == c.Method
}

func (c *CaptureDefine) isHostMatch(session *gomitmproxy.Session) bool {
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(session.Request().Host, "http://"), "https://"), "/") == c.Host
}

type CapturedField struct {
	Field string `yaml:"Field"`
	Value string `yaml:"Value"`
}

func (c *CaptureDefine) captureFromRequestHeader(session *gomitmproxy.Session) (res []CapturedField) {
	for _, cf := range c.Capture {
		val := session.Request().Header.Get(cf.Field)
		res = append(res, CapturedField{
			Field: cf.MapKey,
			Value: cf.mapValue(val),
		})
	}
	return res
}

func (c *CaptureDefine) captureFromRequestBody(session *gomitmproxy.Session) (res []CapturedField) {
	contentType := session.Request().Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return
	}

	a, b := c.copyReader(session.Request().Body, session.Request().Header.Get("Content-Encoding"))
	session.Response().Body = a

	return c.captureFromReader(b)
}

func (c *CaptureDefine) captureFromResponseHeader(session *gomitmproxy.Session) (res []CapturedField) {
	for _, cf := range c.Capture {
		val := session.Response().Header.Get(cf.Field)
		res = append(res, CapturedField{
			Field: cf.MapKey,
			Value: cf.mapValue(val),
		})
	}
	return res
}

func (c *CaptureDefine) captureFromResponseBody(session *gomitmproxy.Session) (res []CapturedField) {
	contentType := session.Response().Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return
	}

	a, b := c.copyReader(session.Response().Body, session.Response().Header.Get("Content-Encoding"))
	session.Response().Body = a
	return c.captureFromReader(b)
}

func (c *CaptureDefine) copyReader(r io.Reader, contentEncoding string) (io.ReadCloser, io.ReadCloser) {
	origin, b := &bytes.Buffer{}, &bytes.Buffer{}
	w := io.MultiWriter(origin, b)
	n, err := io.Copy(w, r)
	log.Info("copy %d bytes, err:%v", n, err)

	if contentEncoding == "gzip" {
		zip, err := gzip.NewReader(b)
		if err != nil {
			log.Error("create gzip reader fail:%s", err.Error())
			return io.NopCloser(origin), io.NopCloser(b)
		}

		return io.NopCloser(origin), zip
	}

	return io.NopCloser(origin), io.NopCloser(b)
}

func (c *CaptureDefine) captureFromReader(body io.Reader) (res []CapturedField) {
	bodyData, err := io.ReadAll(body)
	if err != nil {
		log.Error("read request body fail:%s", err.Error())
		return
	}

	log.Info("request body:%s", string(bodyData))

	for _, cf := range c.Capture {
		fields := strings.Split(cf.Field, ".")

		root, err := sonic.GetFromString(string(bodyData))
		if err != nil {
			log.Error("parse json fail:%s", err.Error())
			continue
		}
		node := &root
		for _, field := range fields {
			node = node.GetByPath(field)
		}

		val, err := node.String()
		if err != nil {
			log.Error("parse json node to string fail:%s", err.Error())
			continue
		}
		res = append(res, CapturedField{
			Field: cf.MapKey,
			Value: cf.mapValue(val),
		})
	}
	return res
}

var captures []CaptureDefine

const (
	OperatorEqual    = "equal"
	OperatorContains = "contains"

	SourceRequestHeader  = "request.header"
	SourceRequestBody    = "request.body"
	SourceResponseHeader = "response.header"
	SourceResponseBody   = "response.body"
)

var (
	values = sync.Map{}
)

func main() {
	//log.SetLevel(log.DEBUG)

	data, err := os.ReadFile("capture.yaml")
	if err != nil {
		log.Fatal(err)
	}

	if err := yaml.Unmarshal(data, &captures); err != nil {
		log.Fatal(err)
	}

	tlsCert, err := tls.LoadX509KeyPair("mycert.pem", "mykey.key")
	if err != nil {
		log.Fatal(err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		log.Fatal(err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
	mitmConfig.SetOrganization("gomitmproxy")  // cert SetOrganization

	proxy := gomitmproxy.NewProxy(gomitmproxy.Config{
		ListenAddr: &net.TCPAddr{
			IP:   net.IPv4(0, 0, 0, 0),
			Port: 8087,
		},
		MITMConfig: mitmConfig,
		OnRequest: func(session *gomitmproxy.Session) (*http.Request, *http.Response) {
			if strings.TrimRight(session.Request().URL.Path, "/") == "/rebate/api/vip" {
				log.Info("header: %v", session.Request().Header.Get("Authorization"))
				values.Store("Authorization", session.Request().Header.Get("Authorization"))
			}
			return nil, nil
		},
		OnResponse: func(session *gomitmproxy.Session) *http.Response {
			doCapture(session)
			return session.Response()
		},
	})

	go func() {
		http.ListenAndServe(":8088", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.URL.Query().Get("key")
			log.Info("key: %v", key)
			v, ok := values.Load(key)
			if !ok {
				return
			}

			w.Write([]byte(v.(string)))
		}))

	}()

	err = proxy.Start()
	if err != nil {
		log.Fatal(err)
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	// Clean up
	//proxy.Close()
}

func doCapture(session *gomitmproxy.Session) {
	for _, cd := range captures {
		doCaptureOne(session, cd)
	}
}

func doCaptureOne(session *gomitmproxy.Session, capture CaptureDefine) {
	if !capture.isPathMatch(session) {
		return
	}

	if !capture.isMethodMatch(session) {
		return
	}

	if capture.Host != "" && !capture.isHostMatch(session) {
		return
	}

	var capturedFields []CapturedField
	switch capture.Source {
	case SourceRequestHeader:
		capturedFields = capture.captureFromRequestHeader(session)
	case SourceRequestBody:
		capturedFields = capture.captureFromRequestBody(session)
	case SourceResponseHeader:
		capturedFields = capture.captureFromResponseHeader(session)
	case SourceResponseBody:
		capturedFields = capture.captureFromResponseBody(session)
	}

	for _, cf := range capturedFields {
		log.Info("key: %v, value: %v", cf.Field, cf.Value)
		values.Store(cf.Field, cf.Value)
	}
}
