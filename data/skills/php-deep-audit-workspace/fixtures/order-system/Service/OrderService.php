<?php
namespace App\Service;

use App\Repository\OrderRepository;

class OrderService
{
    private $orderRepo;

    public function __construct()
    {
        $this->orderRepo = new OrderRepository();
    }

    /**
     * 获取订单详情
     */
    public function getOrderDetail($orderId, $userId)
    {
        // 业务逻辑层没有做额外的安全处理
        // 直接透传 $orderId 到 Repository 层
        $order = $this->orderRepo->findByIdAndUser($orderId, $userId);

        // 格式化金额
        if ($order) {
            $order['amount_formatted'] = number_format($order['amount'], 2);
        }

        return $order;
    }

    /**
     * 搜索订单
     */
    public function searchOrders($userId, $keyword, $sortField)
    {
        // 又一次透传用户输入，没有过滤
        return $this->orderRepo->searchByUser($userId, $keyword, $sortField);
    }
}
