<?php
/**
 * 登录控制器
 * 路由: POST /login, GET /login/callback
 */
namespace App\Controller;

use App\Service\AuthService;

class AuthController
{
    private $authService;

    public function __construct()
    {
        $this->authService = new AuthService();
    }

    /**
     * 用户登录
     * POST /login
     */
    public function login()
    {
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $redirect = $_POST['redirect'] ?? '/';  // 登录后跳转的目标 URL

        if (empty($username) || empty($password)) {
            die('用户名和密码不能为空');
        }

        $user = $this->authService->authenticate($username, $password);

        if ($user) {
            // 登录成功，设置 session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['role'] === 'admin';

            // 漏洞点：$redirect 来自用户输入，用于 header 跳转
            // 经过 authenticate → buildRedirectUrl 后仍无有效过滤
            $targetUrl = $this->authService->buildRedirectUrl($redirect);
            header("Location: {$targetUrl}");
            exit;
        } else {
            die('用户名或密码错误');
        }
    }

    /**
     * SSO 回调
     * GET /login/callback?token=xxx&state=xxx
     */
    public function ssoCallback()
    {
        $token = $_GET['token'];
        $state = $_GET['state'];

        // 追踪：$token 和 $state 传入 AuthService
        $user = $this->authService->ssoVerify($token, $state);

        if ($user) {
            $_SESSION['user_id'] = $user['id'];
            header('Location: /dashboard');
            exit;
        }

        die('SSO 验证失败');
    }
}
