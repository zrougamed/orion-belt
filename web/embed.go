package web

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed static/*
var staticFS embed.FS

// Register mounts the admin UI on the Gin engine.
func Register(r *gin.Engine) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return
	}
	r.StaticFS("/ui", http.FS(sub))
	r.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/ui/")
	})
	r.GET("/admin", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/ui/")
	})
	r.NoRoute(func(c *gin.Context) {
		// SPA fallback for /ui/* only
		if len(c.Request.URL.Path) >= 3 && c.Request.URL.Path[:3] == "/ui" {
			data, err := staticFS.ReadFile("static/index.html")
			if err == nil {
				c.Data(http.StatusOK, "text/html; charset=utf-8", data)
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})
}
