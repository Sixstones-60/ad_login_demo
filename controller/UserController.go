package controller

import (
	"ad_login_demo/common"
	"ad_login_demo/dto"
	"ad_login_demo/model"
	"ad_login_demo/response"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

func Register(ctx *gin.Context) {
	db := common.GetDB()

	// 获取参数
	name := ctx.PostForm("name")
	password := ctx.PostForm("password")

	// 数据验证
	if len(password) < 6 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "密码不能少于6位")

		return
	}
	// 判断用户是否存在
	if isUserExist(db, name) {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "用户已经存在")

		return
	}

	// 创建用户
	hasedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		response.Response(ctx, http.StatusInternalServerError, 500, nil, "加密错误")
		return
	}

	newUser := model.User{
		Name:     name,
		Password: string(hasedPassword),
	}
	db.Create(&newUser)

	// 返回结果

	response.Success(ctx, nil, "注册成功")

}

func Login(ctx *gin.Context) {
	db := common.GetDB()

	// 获取参数
	name := ctx.PostForm("name")
	password := ctx.PostForm("password")

	// 数据验证
	if len(password) < 6 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "密码不能少于6位")
		return
	}
	// 判断用户是否存在
	var user model.User
	db.Where("name = ?", name).First(&user)
	if user.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "用户不存在")

		return
	}

	// 判断密码是否正确
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		response.Fail(ctx, nil, "密码错误")

	}

	// 发放token
	token, err := common.ReleaseToken(user)
	if err != nil {
		response.Response(ctx, http.StatusInternalServerError, 500, nil, "系统异常")

		log.Printf("token generate error : %v", err)
		return
	}
	// 返回结果
	response.Success(ctx, gin.H{"token": token}, "登陆成功")

}

func Info(ctx *gin.Context) {
	user, _ := ctx.Get("user")

	ctx.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{"user": dto.ToUserDto(user.(model.User))}})
}

func isUserExist(db *gorm.DB, name string) bool {
	var user model.User
	db.Where("name = ?", name).First(&user)
	if user.ID != 0 {
		return true
	}
	return false
}
