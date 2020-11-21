package main

import (
	"ad_login_demo/controller"
	"ad_login_demo/middlware"
	"github.com/gin-gonic/gin"
)

func CollectRoute(r *gin.Engine) *gin.Engine {
	r.POST("/api/register", controller.Register)
	r.POST("/api/login", controller.Login)
	r.GET("/api/info", middlware.AuthMiddleware(), controller.Info)

	return r
}
