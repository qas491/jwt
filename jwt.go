package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go" // 导入 JWT 库用于生成和解析令牌
)

// TokenClaims 定义 JWT 令牌中的自定义声明
// 嵌入了 jwt.StandardClaims 结构体，包含标准的 JWT 声明
type TokenClaims struct {
	UserID             string `json:"user_id"`  // 用户ID，在生成令牌时设置
	Username           string `json:"username"` // 用户名，在生成令牌时设置
	Role               string `json:"role"`     // 用户角色，用于权限控制
	jwt.StandardClaims        // 嵌入标准声明，包含 Issuer、ExpiresAt 等字段
}

// TokenConfig 配置 Token 生成和验证的参数
type TokenConfig struct {
	SecretKey         string        // 用于签名和验证令牌的密钥，必须保密
	AccessTokenExpiry time.Duration // 访问令牌的有效期（分钟）
	Issuer            string        // 令牌发行人标识，通常是服务名称
}

// TokenManager 管理 Token 的生成和验证
type TokenManager struct {
	config TokenConfig // 存储 Token 配置信息
}

// NewTokenManager 创建一个新的 Token 管理器实例
func NewTokenManager(config TokenConfig) *TokenManager {
	return &TokenManager{config: config}
}

// GenerateToken 生成 JWT Token
func (tm *TokenManager) GenerateToken(userID, username, role string) (string, error) {
	// 创建自定义声明实例，设置用户信息和标准声明
	claims := &TokenClaims{
		UserID:   userID,   // 设置用户ID
		Username: username, // 设置用户名
		Role:     role,     // 设置用户角色
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * tm.config.AccessTokenExpiry).Unix(), // 设置过期时间
			Issuer:    tm.config.Issuer,                                                 // 设置发行人
			IssuedAt:  time.Now().Unix(),                                                // 设置签发时间
		},
	}

	// 使用 HS256 算法和自定义声明创建新的 JWT 令牌
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 使用密钥对令牌进行签名，生成最终的 JWT 字符串
	return token.SignedString([]byte(tm.config.SecretKey))
}

// ParseToken 解析并验证 JWT Token
func (tm *TokenManager) ParseToken(tokenString string) (*TokenClaims, error) {
	// 解析令牌字符串，使用自定义的解析函数验证签名
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// 验证签名方法是否为预期的 HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// 返回用于验证签名的密钥
		return []byte(tm.config.SecretKey), nil
	})

	if err != nil {
		return nil, err // 解析失败，返回错误
	}

	// 验证令牌是否有效，并将声明转换为自定义的 TokenClaims 类型
	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil // 验证成功，返回解析后的声明
	}

	return nil, errors.New("invalid token") // 验证失败，返回错误
}

// VerifyToken 验证 Token 是否有效
func (tm *TokenManager) VerifyToken(tokenString string) (bool, error) {
	// 调用 ParseToken 方法解析令牌
	_, err := tm.ParseToken(tokenString)
	if err != nil {
		return false, err // 解析失败，令牌无效
	}
	return true, nil // 解析成功，令牌有效
}
