<?php
namespace App\Service;

class FileService
{
    private $uploadDir = '/var/www/uploads/';
    private $exportDir = '/var/www/exports/';
    private $allowedImageTypes = ['image/jpeg', 'image/png', 'image/gif'];

    /**
     * 处理头像上传
     */
    public function processAvatarUpload($file, $userId)
    {
        // 只检查了客户端 MIME 类型 → 可伪造
        if (!in_array($file['type'], $this->allowedImageTypes)) {
            return ['success' => false, 'error' => '不允许的文件类型'];
        }

        // 获取扩展名 - 只检查了原始文件名扩展名 → 可绕过
        $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
        $allowedExt = ['jpg', 'jpeg', 'png', 'gif'];
        if (!in_array(strtolower($ext), $allowedExt)) {
            return ['success' => false, 'error' => '不允许的扩展名'];
        }

        // 文件名包含 user_id，但没有随机化 → 可预测
        $newFilename = "avatar_{$userId}.{$ext}";
        $targetPath = $this->uploadDir . $newFilename;

        // move_uploaded_file 本身安全，但文件名未随机化 + 扩展名可绕过
        if (move_uploaded_file($file['tmp_name'], $targetPath)) {
            $url = "/uploads/{$newFilename}";
            return ['success' => true, 'url' => $url];
        }

        return ['success' => false, 'error' => '文件保存失败'];
    }

    /**
     * 保存导出文件
     */
    public function saveExport($filename, $content)
    {
        // 路径穿越漏洞：$filename 来自用户输入，未做 basename() 过滤
        // 攻击者可以传入 ../../config/database.php 覆写关键文件
        $targetPath = $this->exportDir . $filename;

        // 检查目录是否存在
        $dir = dirname($targetPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);  // 创建目录，可能被利用创建任意目录
        }

        // 写入文件 — 文件路径完全由用户控制
        return file_put_contents($targetPath, $content) !== false;
    }
}
