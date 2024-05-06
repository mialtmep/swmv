package main

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	go_qr "github.com/piglig/go-qr"
)

type Thumbnail struct {
	Thumb    *string // base64 encoded 200x200 image
	Name     string
	Duration time.Duration
	Size     int64 // in MB
	Codec    string
}

type Template struct {
	templates *template.Template
}

//go:embed static
var staticFS embed.FS

var (
	workDir         string
	validExtentions *regexp.Regexp
)

var (
	port        string
	authString  string
	user        string
	pass        string
	cert        string
	key         string
	quiet       bool
	queryAuth   bool
	pictures    bool
	qr          bool
	ffmpegPath  string
	ffprobePath string
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	flag.StringVar(&port, "port", "8080", "Working port")
	flag.StringVar(&authString, "auth", "", "Auth creds in user:password form or just a key in query auth mode")
	flag.StringVar(&cert, "cert", "", "Cert path")
	flag.StringVar(&key, "key", "", "Key path")
	flag.BoolVar(&queryAuth, "query_auth", false, "Auth using URL query instead of normal auth")
	flag.BoolVar(&qr, "qr", false, "Print address as QR code")
	// TODO: (?) log levels
	flag.BoolVar(&quiet, "quiet", false, "Suppress logging")
	flag.BoolVar(&pictures, "pictures", false, "Also show pictures")
	flag.StringVar(&ffmpegPath, "ffmpeg", "ffmpeg", "FFmpeg executable path")
	flag.StringVar(&ffprobePath, "ffprobe", "ffprobe", "FFprobe executable path")
	flag.Parse()

	switch len(flag.Args()) {
	case 0:
		workDir = "."
	case 1:
		workDir = flag.Arg(0)
	default:
		log.Fatal("too many unnamed arguments")
	}

	if pictures {
		validExtentions = regexp.MustCompile("(?i)(webm|mp4|mov|gif|png|jpg|jpeg|webp|gif|jfif)$")
	} else {
		validExtentions = regexp.MustCompile("(?i)(webm|mp4|mov)$")
	}

	e := echo.New()
	e.Pre(middleware.HTTPSRedirect())
	e.HideBanner = true

	e.Use(middleware.Recover())
	e.Use(middleware.Gzip())
	if !quiet {
		e.Use(middleware.Logger())
	}

	if len(authString) != 0 {
		if queryAuth {
			e.Use(middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
				KeyLookup: "query:key",
				Validator: qAuth,
			}))
		} else {
			a := strings.Split(authString, ":")
			user = a[0]
			pass = a[1]
			e.Use(middleware.BasicAuth(auth))
		}
	}
	assetHandler := http.FileServer(http.FS(staticFS))

	e.Renderer = initRenderer()
	e.GET("/static/*", echo.WrapHandler(http.StripPrefix("", assetHandler)))
	e.Static("/", workDir)
	e.GET("/", images)
	e.GET("/test", tlsTest)

	if qr {
		printQR()
	}
	if len(cert) != 0 && len(key) != 0 {
		if _, err := os.Stat(cert); err != nil {
			log.Fatal("Cert file cannot be accessed")
		}
		if _, err := os.Stat(key); err != nil {
			log.Fatal("Key file cannot be accessed")
		}

		e.Logger.Fatal(e.StartTLS(fmt.Sprint(":", port), cert, key))

	} else {
		e.Logger.Fatal(e.Start(fmt.Sprint(":", port)))
	}
}

func initRenderer() *Template {
	funcMap := template.FuncMap{
		"url": func(s string) template.URL {
			return template.URL(s)
		},
		"prettyTime": func(d time.Duration) string {
			if d.Minutes() < 1 && d.Seconds() < 1 {
				return ""
			} else {
				return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
			}
		},
		"prettyName": func(n string) string {
			// n = strings.ReplaceAll(n, "-", " ")
			// n = strings.ReplaceAll(n, "_", " ")
			if []rune(n)[0] == []rune("/")[0] {
				n = n[1 : len(n)-1]
			}
			s := strings.Split(n, ".")
			return strings.Join(s[0:len(s)-1], "")
		},
		"prettySize": func(size int64) string {
			units := []string{"B", "KB", "MB", "GB", "TB"}
			var unit int
			for size >= 1024 && unit < len(units)-1 {
				size /= 1024
				unit++
			}
			return fmt.Sprintf("%d %s", size, units[unit])
		},
		"authHref": func(h string) string {
			h = strings.TrimSpace(h)
			if queryAuth && authString != "" {
				return strings.Join([]string{h, authString}, "?key=")
			}
			return h
		},
	}
	t := &Template{
		templates: template.Must(template.New("main").Funcs(funcMap).Parse(func() string {
			s, err := staticFS.ReadFile("static/index.html")
			e(err)
			return string(s)
		}())),
	}
	return t
}

func auth(username, password string, c echo.Context) (bool, error) {
	if subtle.ConstantTimeCompare([]byte(username), []byte(user)) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(pass)) == 1 {
		return true, nil
	}
	return false, nil
}

func qAuth(key string, c echo.Context) (bool, error) {
	if subtle.ConstantTimeCompare([]byte(key), []byte(authString)) == 1 {
		return true, nil
	}
	return false, nil
}

func tlsTest(c echo.Context) error {
	req := c.Request()
	return c.HTML(http.StatusOK, fmt.Sprint("<pre>", req, "</pre>"))
}

func images(c echo.Context) error {
	return c.Render(http.StatusOK, "main", ffmpegThumbs(workDir))
}

func ffmpegThumbs(path string) map[string]Thumbnail {
	re := validExtentions
	dirs, err := getFiles(path)
	e(err)

	wg := new(sync.WaitGroup)
	writeMutex := sync.Mutex{}
	limit := semaphore.NewWeighted(10)

	images := map[string]Thumbnail{}
	conf := FFConfig{
		ffmpegPath:  ffmpegPath,
		ffprobePath: ffprobePath,
	}

	for _, v := range dirs {
		wg.Add(1)
		go func(name string, thumbnailWrite *sync.Mutex, s *semaphore.Weighted) {
			defer wg.Done()
			defer s.Release(1)

			s.Acquire(context.Background(), 1)
			file, err := os.Open(name)
			e(err)
			fstat, err := file.Stat()
			e(err)
			file.Close()

			if !re.MatchString(name) {
				return
			}

			p, err := MakeThumbnail(conf, name)
			if err != nil {
				if !quiet {
					log.Println(err)
				}
				return
			}

			path := ""
			if workDir != "." {
				path = strings.Replace(name, workDir, "", 1)
			} else {
				path = name
			}
			thumbnailWrite.Lock()
			images[name] = Thumbnail{
				Thumb:    &p.thumbnail,
				Name:     path,
				Duration: p.duration,
				Size:     fstat.Size(),
				Codec:    "todo",
			}
			thumbnailWrite.Unlock()
		}(v, &writeMutex, limit)
	}
	wg.Wait()
	if !(quiet) {
		log.Printf("Parsed %v objects\n", len(images))
	}
	return images
}

func e(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func getNetworkAddress() string {
	if cert != "" {
		c, e := os.ReadFile(cert)
		if e != nil {
			log.Fatal(e)
		}
		block, rest := pem.Decode([]byte(c))
		if block == nil || len(rest) > 0 {
			log.Fatal("Certificate decoding error")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		if queryAuth && authString != "" {
			return fmt.Sprintf("https://%s:%s?key=%s", cert.DNSNames[0], port, authString)
		} else {
			return fmt.Sprintf("https://%s:%s", cert.DNSNames[0], port)
		}
	} else {
		// получение локального IP адреса устройства
		conn, err := net.Dial("udp", "0.0.0.0:1")
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		return fmt.Sprintf("http://%s:%s", localAddr.IP.String(), port)
	}
}

func getFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			files = append(files, path)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

func printQR() {
	addr := getNetworkAddress()
	q, er := go_qr.EncodeText(addr, go_qr.Low)
	e(er)
	for y := range q.GetSize() {
		for x := range q.GetSize() {
			if q.GetModule(x, y) {
				print("██")
			} else {
				print("  ")
			}
		}
		println()
	}
	fmt.Printf("%s\n", addr)
}
