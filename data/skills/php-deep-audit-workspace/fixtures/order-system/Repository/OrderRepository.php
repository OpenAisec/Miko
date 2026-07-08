<?php
namespace App\Repository;

class OrderRepository
{
    private $db;

    public function __construct()
    {
        $this->db = new \mysqli('localhost', 'root', 'password', 'shop');
        $this->db->set_charset('utf8');
    }

    /**
     * 根据 ID 和用户 ID 查找订单
     */
    public function findByIdAndUser($orderId, $userId)
    {
        // 漏洞点 1：SQL 注入 — $orderId 直接拼接到 SQL 中
        // 从 Controller → Service → Repository，三层穿透无过滤
        $sql = "SELECT * FROM orders WHERE id = {$orderId} AND user_id = {$userId}";
        $result = $this->db->query($sql);

        if ($result && $result->num_rows > 0) {
            return $result->fetch_assoc();
        }

        return null;
    }

    /**
     * 搜索用户订单
     */
    public function searchByUser($userId, $keyword, $sortField)
    {
        // 漏洞点 2：$sortField 拼接到 ORDER BY — 不能参数化，需要白名单
        $sql = "SELECT * FROM orders WHERE user_id = {$userId}";
        if (!empty($keyword)) {
            $keyword = $this->db->real_escape_string($keyword);
            $sql .= " AND (order_no LIKE '%{$keyword}%' OR product_name LIKE '%{$keyword}%')";
        }
        $sql .= " ORDER BY {$sortField} DESC";  // 漏洞：ORDER BY 注入

        return $this->db->query($sql);
    }
}
