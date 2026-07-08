<?php
/**
 * 文件上传控制器
 * 路由: POST /upload/avatar, POST /upload/export
 */
namespace App\Controller;

use App\Service\FileService;

class UploadController
{
    private $fileService;

    public function __construct()
    {
        $this->fileService = new FileService();
    }

    /**
     * 上传头像
     * POST /upload/avatar
     */
    public function uploadAvatar()
    {
        if (empty($_SESSION['user_id'])) {
            die('请先登录');
        }

        if (!isset($_FILES['avatar'])) {
            die('请选择文件');
        }

        $file = $_FILES['avatar'];
        $userId = $_SESSION['user_id'];

        // 控制器层没有做安全检查，全部委托给 FileService
        $result = $this->fileService->processAvatarUpload($file, $userId);

        if ($result['success']) {
            echo "上传成功: " . $result['url'];
        } else {
            echo "上传失败: " . $result['error'];
        }
    }

    /**
     * 导出报表
     * POST /upload/export
     * 漏洞点：用户控制导出文件名，导致路径穿越写文件
     */
    public function exportReport()
    {
        if (empty($_SESSION['user_id'])) {
            die('请先登录');
        }

        $filename = $_POST['filename'] ?? 'report.csv';  // 用户可控
        $content = $_POST['content'] ?? '';

        // 传入 FileService 处理
        $result = $this->fileService->saveExport($filename, $content);

        if ($result) {
            echo "导出成功";
        } else {
            echo "导出失败";
        }
    }
}
