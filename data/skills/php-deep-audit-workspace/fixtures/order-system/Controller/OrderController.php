<?php
/**
 * 订单控制器 - 处理订单相关请求
 * 路由: GET /order/detail
 * 需要登录
 */
namespace App\Controller;

use App\Service\OrderService;

class OrderController
{
    private $orderService;

    public function __construct()
    {
        $this->orderService = new OrderService();
    }

    /**
     * 订单详情
     * GET /order/detail?id=123
     */
    public function detail()
    {
        // 检查登录
        if (empty($_SESSION['user_id'])) {
            header('Location: /login');
            exit;
        }

        $orderId = $_GET['order_id'];
        // 简单的非空校验，没有任何安全过滤
        if (empty($orderId)) {
            die('订单ID不能为空');
        }

        $userId = $_SESSION['user_id'];

        // 调用 Service 层获取订单
        $order = $this->orderService->getOrderDetail($orderId, $userId);

        if (!$order) {
            die('订单不存在');
        }

        // 渲染页面
        include __DIR__ . '/../View/order_detail.php';
    }

    /**
     * 订单搜索
     * GET /order/search?keyword=xxx&sort=created_at
     */
    public function search()
    {
        if (empty($_SESSION['user_id'])) {
            header('Location: /login');
            exit;
        }

        $keyword = $_GET['keyword'] ?? '';
        $sortField = $_GET['sort'] ?? 'created_at';  // 用户可控

        $userId = $_SESSION['user_id'];
        $orders = $this->orderService->searchOrders($userId, $keyword, $sortField);

        include __DIR__ . '/../View/order_list.php';
    }
}
