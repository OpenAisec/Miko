<?php
namespace App\Service;

class AuthService
{
    private $db;

    public function __construct()
    {
        $this->db = new \mysqli('localhost', 'root', 'password', 'shop');
        $this->db->set_charset('gbk');  // 注意：GBK 编码！
    }

    /**
     * 用户认证
     */
    public function authenticate($username, $password)
    {
        // 对用户名做转义
        $username = addslashes($username);
        $password = md5($password);  // MD5 不够安全，但这不是本次审计的重点

        // addslashes + GBK 编码 → 宽字节注入风险
        // 例如：username=%df' OR 1=1--
        // addslashes 后变成 %df%5c' → GBK 解释为 運' → 引号逃逸
        $sql = "SELECT * FROM users WHERE username = '{$username}' AND password = '{$password}'";
        $result = $this->db->query($sql);

        if ($result && $result->num_rows > 0) {
            return $result->fetch_assoc();
        }

        return null;
    }

    /**
     * 构建登录后跳转的 URL
     */
    public function buildRedirectUrl($url)
    {
        // 试图做安全检查，但实现不完整
        // 只检查了是否以 http:// 或 https:// 开头
        if (strpos($url, 'http://') !== false || strpos($url, 'https://') !== false) {
            return '/';  // 外部 URL 则跳回首页
        }

        return $url;  // 漏洞：//evil.com 可以绕过，导致开放重定向
        // 攻击者可以构造 redirect=//evil.com
    }

    /**
     * SSO 验证
     */
    public function ssoVerify($token, $state)
    {
        // $token 直接用于 HTTP 请求
        $url = "https://sso.example.com/verify?token={$token}&state={$state}";

        // 漏洞点：curl 请求的外部 URL，拼接用户输入
        // 虽然 $url 被用于 curl 请求，但上下文是去请求 SSO 服务器
        // 需要判断：$token 是否可能被控制来发起 SSRF？
        // 实际上 token 作为 URL 参数拼接，如果 token 中包含 &redirect_to=http://internal 可以篡改 SSO 请求参数
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($ch);
        curl_close($ch);

        $data = json_decode($response, true);
        if ($data && isset($data['user_id'])) {
            return ['id' => $data['user_id'], 'username' => $data['username']];
        }

        return null;
    }
}
