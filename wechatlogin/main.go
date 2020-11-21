package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
)

type WXLoginResp struct {
	OpenId     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionId    string `json:"unionid"`
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
}

func main() {
	//http.HandleFunc("/login", WXLetLogin)
	//http.ListenAndServe(":8888", nil)
	r := gin.Default()
	r.GET("/login", AppletWeChatLogin)
	r.Run(":8888")

}

// 这个函数以 code 作为输入, 返回调用微信接口得到的对象指针和异常情况
func WXLogin(code string) (*WXLoginResp, error) {
	url := "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code"

	// 合成url, 这里的appId和secret是在微信公众平台上获取的

	url = fmt.Sprintf(url, "wx089346dbe48b7a40", "1df3b1c47fd08d1e305bfc66f9f28286", code)

	// 创建http get请求
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 解析http请求中body 数据到我们定义的结构体中
	wxResp := WXLoginResp{}
	decoder := json.NewDecoder(resp.Body)

	if err := decoder.Decode(&wxResp); err != nil {
		return nil, err
	}

	// 判断微信接口返回的是否是一个异常情况
	if wxResp.ErrCode != 0 {
		return nil, errors.New(fmt.Sprintf("ErrCode:%s  ErrMsg:%s", wxResp.ErrCode, wxResp.ErrMsg))
	}

	return &wxResp, nil
}

//func WXLetLogin(w http.ResponseWriter, r *http.Request) {
//	if r.Method != http.MethodPost {
//		return
//	}
//
//	var codeMap map[string]string
//	err := json.NewDecoder(r.Body).Decode(&codeMap)
//	if err != nil {
//		return
//	}
//	defer r.Body.Close()
//
//	// 返回json数据
//	code := codeMap["code"]
//	openid, err := WXLogin(code)
//	if err != nil {
//		return
//	}
//	var op, _ = json.Marshal(&openid)
//	w.Header().Set("Content-Type", "application-json")
//	io.Copy(w, strings.NewReader(string(op)))
//
//	// 保存登录态
//	//session := sessions.Default(c)
//	//session.Set("openid", wxLoginResp.OpenId)
//	//session.Set("sessionKey", wxLoginResp.SessionKey )
//
//}
// /wechat/applet_login?code=xxx [get]  路由
// 微信小程序登录
func AppletWeChatLogin(c *gin.Context) {
	code := c.Query("code") //  获取code
	// 根据code获取 openID 和 session_key
	//wxLoginResp,err := models.WXLogin(code)
	//if err != nil {
	//	c.JSON(400, err)
	//	return
	//}
	wxLoginResp, err := WXLogin(code)

	if err != nil {
		fmt.Println("error is ", err)
		return
	}
	c.JSON(http.StatusOK, wxLoginResp)
	//c.JSON(http.StatusOK, gin.H{
	//	"message":code,
	//})
	// 保存登录态
	sess := sessions.Default(c)
	sess.Set("openid", wxLoginResp.OpenId)
	sess.Set("sessionKey", wxLoginResp.SessionKey)

	// 这里用openid和sessionkey的串接 进行MD5之后作为该用户的自定义登录态
	mySession := GetMD5Encode(wxLoginResp.OpenId + wxLoginResp.SessionKey)
	// 接下来可以将openid 和 sessionkey, mySession 存储到数据库中,
	// 但这里要保证mySession 唯一, 以便于用mySession去索引openid 和sessionkey
	c.String(200, mySession)

}

// 将一个字符串进行MD5加密后返回加密后的字符串
func GetMD5Encode(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// 校验微信返回的用户数据
func ValidateUserInfo(rawData, sessionKey, signature string) bool {
	signature2 := GetSha1(rawData + sessionKey)
	return signature == signature2
}

// SHA-1 加密
func GetSha1(str string) string {
	data := []byte(str)
	has := sha1.Sum(data)
	res := fmt.Sprintf("%x", has) //将[]byte转成16进制
	return res
}
