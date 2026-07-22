# 自动化脚本详解 (Automation)

## 目录

1. [自动化概述](#自动化概述)
2. [模拟输入](#模拟输入)
3. [图像识别](#图像识别)
4. [OCR 文字识别](#ocr-文字识别)
5. [坐标系与窗口适配](#坐标系与窗口适配)
6. [AutoHotKey 脚本](#autohotkey-脚本)
7. [实战案例](#实战案例)

---

## 自动化概述

游戏自动化是通过脚本模拟玩家操作，实现自动挂机、刷副本、日常任务等功能。

### 技术路线

| 方式 | 原理 | 适用场景 |
|------|------|----------|
| 键鼠模拟 | 模拟鼠标键盘输入 | 简单重复操作 |
| 图像识别 | 截图 + 模板匹配 | 需要判断画面内容 |
| 内存读写 | 直接读取游戏数据 | 数据精确获取 |
| 协议模拟 | 直接发送网络包 | 无需游戏客户端 |

### 开发流程

```
1. 分析操作流程 → 分解为步骤
2. 确定触发条件 → 何时执行什么
3. 选择识别方式 → 图像/内存/协议
4. 编写脚本 → 实现自动化逻辑
5. 测试优化 → 稳定性和效率
```

---

## 模拟输入

### Windows API

```c
#include <windows.h>

// 模拟鼠标
void mouse_move(int x, int y) {
    SetCursorPos(x, y);
}

void mouse_click(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0);
    Sleep(50);
    mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0);
}

void mouse_right_click(int x, int y) {
    SetCursorPos(x, y);
    mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0);
    Sleep(50);
    mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0);
}

// 模拟键盘
void key_press(WORD vk) {
    keybd_event(vk, 0, 0, 0);
    Sleep(50);
    keybd_event(vk, 0, KEYEVENTF_KEYUP, 0);
}

void key_press_combo(WORD vk1, WORD vk2) {
    keybd_event(vk1, 0, 0, 0);
    keybd_event(vk2, 0, 0, 0);
    Sleep(50);
    keybd_event(vk2, 0, KEYEVENTF_KEYUP, 0);
    keybd_event(vk1, 0, KEYEVENTF_KEYUP, 0);
}

// SendInput 方式（更现代）
void send_mouse_click(int x, int y) {
    INPUT input = {};
    input.type = INPUT_MOUSE;
    
    // 移动
    input.mi.dx = x * (65535 / GetSystemMetrics(SM_CXSCREEN));
    input.mi.dy = y * (65535 / GetSystemMetrics(SM_CYSCREEN));
    input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
    SendInput(1, &input, sizeof(INPUT));
    
    // 点击
    input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
    SendInput(1, &input, sizeof(INPUT));
    
    input.mi.dwFlags = MOUSEEVENTF_LEFTUP;
    SendInput(1, &input, sizeof(INPUT));
}
```

### Python 实现

```python
import pyautogui
import time

# 安全设置
pyautogui.FAILSAFE = True  # 鼠标移到左上角触发异常
pyautogui.PAUSE = 0.1       # 每次操作间隔

# 鼠标操作
pyautogui.moveTo(100, 200)          # 移动到坐标
pyautogui.click(100, 200)           # 点击
pyautogui.doubleClick(100, 200)     # 双击
pyautogui.rightClick(100, 200)      # 右键
pyautogui.drag(100, 0, duration=0.5)  # 拖拽

# 键盘操作
pyautogui.press('space')            # 按键
pyautogui.hotkey('ctrl', 'c')       # 组合键
pyautogui.typewrite('hello', interval=0.05)  # 输入文字

# 相对移动
pyautogui.moveRel(100, 0)  # 相对移动
```

### 后台模拟（发送到窗口句柄）

```python
import win32api
import win32gui
import win32con

def background_click(hwnd, x, y):
    """后台点击（不干扰前台操作）"""
    lparam = win32api.MAKELONG(x, y)
    win32gui.PostMessage(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
    time.sleep(0.05)
    win32gui.PostMessage(hwnd, win32con.WM_LBUTTONUP, 0, lparam)

def background_key(hwnd, vk):
    """后台按键"""
    win32gui.PostMessage(hwnd, win32con.WM_KEYDOWN, vk, 0)
    time.sleep(0.05)
    win32gui.PostMessage(hwnd, win32con.WM_KEYUP, vk, 0)

# 获取窗口句柄
hwnd = win32gui.FindWindow(None, "游戏窗口标题")
if hwnd:
    background_click(hwnd, 100, 200)
    background_key(hwnd, win32con.VK_SPACE)
```

---

## 图像识别

### OpenCV 模板匹配

```python
import cv2
import numpy as np
from PIL import ImageGrab

def screenshot(region=None):
    """截取屏幕"""
    img = ImageGrab.grab(bbox=region)
    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

def find_template(template_path, region=None, threshold=0.8):
    """在屏幕上查找模板图像"""
    screen = screenshot(region)
    template = cv2.imread(template_path)
    
    result = cv2.matchTemplate(screen, template, cv2.TM_CCOEFF_NORMED)
    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
    
    if max_val >= threshold:
        # 计算中心点
        h, w = template.shape[:2]
        center_x = max_loc[0] + w // 2
        center_y = max_loc[1] + h // 2
        
        # 如果指定了区域，加上区域偏移
        if region:
            center_x += region[0]
            center_y += region[1]
        
        return (center_x, center_y, max_val)
    
    return None

def find_all_templates(template_path, region=None, threshold=0.8):
    """查找所有匹配位置"""
    screen = screenshot(region)
    template = cv2.imread(template_path)
    
    result = cv2.matchTemplate(screen, template, cv2.TM_CCOEFF_NORMED)
    locations = np.where(result >= threshold)
    
    h, w = template.shape[:2]
    points = []
    for pt in zip(*locations[::-1]):
        center_x = pt[0] + w // 2
        center_y = pt[1] + h // 2
        if region:
            center_x += region[0]
            center_y += region[1]
        points.append((center_x, center_y))
    
    # 去重（相近的点合并）
    return merge_nearby_points(points, distance=10)

def merge_nearby_points(points, distance=10):
    """合并相近的点"""
    merged = []
    used = [False] * len(points)
    
    for i, p1 in enumerate(points):
        if used[i]:
            continue
        cluster = [p1]
        for j, p2 in enumerate(points):
            if i != j and not used[j]:
                if abs(p1[0]-p2[0]) < distance and abs(p1[1]-p2[1]) < distance:
                    cluster.append(p2)
                    used[j] = True
        
        # 取平均值
        avg_x = sum(p[0] for p in cluster) // len(cluster)
        avg_y = sum(p[1] for p in cluster) // len(cluster)
        merged.append((avg_x, avg_y))
        used[i] = True
    
    return merged
```

### 颜色识别

```python
import cv2
import numpy as np

def find_color(region, target_color, tolerance=20):
    """在指定区域查找目标颜色"""
    screen = screenshot(region)
    
    # 转换颜色空间
    target_bgr = target_color[::-1]  # RGB -> BGR
    
    # 创建颜色范围
    lower = np.array([max(0, c - tolerance) for c in target_bgr])
    upper = np.array([min(255, c + tolerance) for c in target_bgr])
    
    # 创建掩码
    mask = cv2.inRange(screen, lower, upper)
    
    # 查找匹配的像素
    locations = np.where(mask > 0)
    if len(locations[0]) > 0:
        # 返回第一个匹配位置
        y, x = locations[0][0], locations[1][0]
        return (x + region[0], y + region[1])
    
    return None

def find_color_bar(region, bar_color, bg_color):
    """识别进度条（血条、蓝条等）"""
    screen = screenshot(region)
    
    # 查找进度条区域
    bar_mask = cv2.inRange(screen, 
                           np.array(bar_color[::-1]) - 20,
                           np.array(bar_color[::-1]) + 20)
    
    # 计算填充比例
    bar_pixels = np.count_nonzero(bar_mask)
    total_width = region[2] - region[0]
    
    # 按列统计
    col_counts = np.count_nonzero(bar_mask, axis=0)
    filled_width = np.count_nonzero(col_counts)
    
    percentage = filled_width / total_width * 100
    return percentage
```

### 特征点匹配

```python
import cv2

def feature_match(img1_path, img2_path, min_match_count=10):
    """特征点匹配（适用于缩放、旋转场景）"""
    img1 = cv2.imread(img1_path, cv2.IMREAD_GRAYSCALE)
    img2 = cv2.imread(img2_path, cv2.IMREAD_GRAYSCALE)
    
    # SIFT 特征检测
    sift = cv2.SIFT_create()
    kp1, des1 = sift.detectAndCompute(img1, None)
    kp2, des2 = sift.detectAndCompute(img2, None)
    
    # FLANN 匹配
    FLANN_INDEX_KDTREE = 1
    index_params = dict(algorithm=FLANN_INDEX_KDTREE, trees=5)
    search_params = dict(checks=50)
    flann = cv2.FlannBasedMatcher(index_params, search_params)
    matches = flann.knnMatch(des1, des2, k=2)
    
    # 筛选好的匹配
    good_matches = []
    for m, n in matches:
        if m.distance < 0.7 * n.distance:
            good_matches.append(m)
    
    if len(good_matches) >= min_match_count:
        # 计算变换矩阵
        src_pts = np.float32([kp1[m.queryIdx].pt for m in good_matches]).reshape(-1, 1, 2)
        dst_pts = np.float32([kp2[m.trainIdx].pt for m in good_matches]).reshape(-1, 1, 2)
        M, mask = cv2.findHomography(src_pts, dst_pts, cv2.RANSAC, 5.0)
        return M
    
    return None
```

---

## OCR 文字识别

### Tesseract OCR

```python
import pytesseract
from PIL import Image

# 设置 Tesseract 路径
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

def ocr_region(region, lang='chi_sim+eng'):
    """识别屏幕区域的文字"""
    img = ImageGrab.grab(bbox=region)
    text = pytesseract.image_to_string(img, lang=lang)
    return text.strip()

def ocr_number(region):
    """识别数字"""
    img = ImageGrab.grab(bbox=region)
    # 预处理：灰度化 + 二值化
    img = img.convert('L')
    img = img.point(lambda x: 0 if x < 128 else 255)
    
    text = pytesseract.image_to_string(img, config='--psm 7 digits')
    # 提取数字
    numbers = ''.join(c for c in text if c.isdigit())
    return int(numbers) if numbers else None
```

### PaddleOCR（中文推荐）

```python
from paddleocr import PaddleOCR

ocr = PaddleOCR(use_angle_cls=True, lang='ch')

def ocr_screen(region=None):
    """使用 PaddleOCR 识别屏幕文字"""
    img = ImageGrab.grab(bbox=region)
    img_path = '/tmp/screenshot.png'
    img.save(img_path)
    
    result = ocr.ocr(img_path, cls=True)
    
    texts = []
    for line in result[0]:
        box, (text, confidence) = line
        texts.append({
            'text': text,
            'confidence': confidence,
            'position': box
        })
    
    return texts
```

### EasyOCR

```python
import easyocr

reader = easyocr.Reader(['ch_sim', 'en'])

def ocr_image(image_path):
    """识别图片文字"""
    results = reader.readtext(image_path)
    for (bbox, text, prob) in results:
        print(f"[{prob:.2f}] {text}")
    return results
```

---

## 坐标系与窗口适配

### 窗口坐标系

```python
import win32gui

def get_window_rect(hwnd):
    """获取窗口矩形"""
    rect = win32gui.GetWindowRect(hwnd)
    return {
        'left': rect[0],
        'top': rect[1],
        'right': rect[2],
        'bottom': rect[3],
        'width': rect[2] - rect[0],
        'height': rect[3] - rect[1]
    }

def get_client_rect(hwnd):
    """获取客户区矩形（不含标题栏和边框）"""
    rect = win32gui.GetClientRect(hwnd)
    point = win32gui.ClientToScreen(hwnd, (0, 0))
    return {
        'left': point[0],
        'top': point[1],
        'right': point[0] + rect[2],
        'bottom': point[1] + rect[3],
        'width': rect[2],
        'height': rect[3]
    }

def screen_to_client(hwnd, x, y):
    """屏幕坐标转客户区坐标"""
    point = win32gui.ScreenToClient(hwnd, (x, y))
    return point

def client_to_screen(hwnd, x, y):
    """客户区坐标转屏幕坐标"""
    point = win32gui.ClientToScreen(hwnd, (x, y))
    return point
```

### DPI 适配

```python
import ctypes

def get_dpi_scale():
    """获取 DPI 缩放比例"""
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
    hdc = ctypes.windll.user32.GetDC(0)
    dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)  # LOGPIXELSX
    ctypes.windll.user32.ReleaseDC(0, hdc)
    return dpi / 96.0

def scale_coord(x, y):
    """根据 DPI 缩放坐标"""
    scale = get_dpi_scale()
    return (int(x * scale), int(y * scale))
```

### 分辨率适配

```python
def relative_coord(x, y, ref_width=1920, ref_height=1080):
    """将坐标转换为相对坐标（基于参考分辨率）"""
    screen_width = win32api.GetSystemMetrics(0)
    screen_height = win32api.GetSystemMetrics(1)
    
    rel_x = int(x * screen_width / ref_width)
    rel_y = int(y * screen_height / ref_height)
    return (rel_x, rel_y)
```

---

## AutoHotKey 脚本

### 基础语法

```ahk
; 热键定义
F1::  ; 按 F1 触发
    Click, 100, 200  ; 点击坐标
    Sleep, 100
    Send, {Space}    ; 按空格
return

; 循环挂机
F2::
    Loop {
        Click, 500, 300
        Sleep, 1000
        Click, 600, 400
        Sleep, 1000
        if (GetKeyState("F3", "P"))  ; 按 F3 停止
            break
    }
return

; 图像查找点击
F3::
    ImageSearch, FoundX, FoundY, 0, 0, A_ScreenWidth, A_ScreenHeight, button.png
    if (ErrorLevel = 0) {
        Click, %FoundX%, %FoundY%
    }
return
```

### 高级功能

```ahk
; 像素颜色检测
F4::
    PixelGetColor, color, 100, 200, RGB
    if (color = 0xFF0000) {
        MsgBox, 发现红色！
    }
return

; 窗口操作
F5::
    WinActivate, 游戏窗口标题
    WinWaitActive, 游戏窗口标题
    Click, 100, 200
return

; 后台操作（不激活窗口）
F6::
    ControlClick, x100 y200, 游戏窗口标题
return
```

---

## 实战案例

### 案例：自动刷副本脚本

```python
import time
import pyautogui

class AutoDungeon:
    """自动刷副本"""
    
    def __init__(self):
        self.running = False
        self.dungeon_count = 0
    
    def find_and_click(self, template, timeout=10):
        """查找并点击模板"""
        start = time.time()
        while time.time() - start < timeout:
            pos = find_template(template)
            if pos:
                pyautogui.click(pos[0], pos[1])
                return True
            time.sleep(0.5)
        return False
    
    def enter_dungeon(self):
        """进入副本"""
        # 点击副本入口
        if not self.find_and_click('dungeon_entrance.png'):
            return False
        
        time.sleep(1)
        
        # 点击确认
        if not self.find_and_click('confirm.png'):
            return False
        
        time.sleep(3)  # 等待加载
        return True
    
    def auto_battle(self):
        """自动战斗"""
        # 点击自动战斗按钮
        self.find_and_click('auto_battle.png')
        
        # 等待战斗结束
        while True:
            # 检测战斗结束标志
            if find_template('battle_victory.png'):
                print("战斗胜利！")
                break
            if find_template('battle_defeat.png'):
                print("战斗失败！")
                break
            time.sleep(1)
        
        # 点击领取奖励
        time.sleep(1)
        self.find_and_click('claim_reward.png')
    
    def run(self, target_count=10):
        """运行自动刷副本"""
        self.running = True
        
        while self.running and self.dungeon_count < target_count:
            print(f"开始第 {self.dungeon_count + 1} 次副本...")
            
            if not self.enter_dungeon():
                print("进入副本失败，重试...")
                time.sleep(5)
                continue
            
            self.auto_battle()
            self.dungeon_count += 1
            
            print(f"完成！已刷 {self.dungeon_count} 次")
            time.sleep(2)
        
        self.running = False

# 使用
bot = AutoDungeon()
bot.run(target_count=10)
```

### 案例：自动日常任务

```python
class DailyTask:
    """自动日常任务"""
    
    def __init__(self):
        self.tasks = [
            ('签到', self.daily_sign_in),
            ('领取体力', self.claim_stamina),
            ('竞技场', self.arena_battle),
            ('公会捐献', self.guild_donate),
            ('领取邮件', self.claim_mail),
        ]
    
    def daily_sign_in(self):
        """每日签到"""
        self.find_and_click('sign_in_btn.png')
        time.sleep(1)
        self.find_and_click('claim_sign_in.png')
    
    def claim_stamina(self):
        """领取体力"""
        self.find_and_click('stamina_icon.png')
        time.sleep(1)
        self.find_and_click('claim_stamina_btn.png')
    
    def run_all(self):
        """执行所有日常任务"""
        for name, func in self.tasks:
            print(f"执行任务: {name}")
            try:
                func()
                print(f"  {name} 完成")
            except Exception as e:
                print(f"  {name} 失败: {e}")
            time.sleep(2)
        
        print("所有日常任务完成！")
```

### 案例：颜色识别血量监控

```python
def monitor_health():
    """监控血量并自动回血"""
    # 血条区域 (x, y, width, height)
    health_bar_region = (100, 50, 300, 20)
    
    while True:
        # 检测血量百分比
        health_percent = find_color_bar(
            health_bar_region,
            bar_color=(255, 0, 0),  # 红色血条
            bg_color=(50, 50, 50)    # 灰色背景
        )
        
        print(f"当前血量: {health_percent:.1f}%")
        
        if health_percent < 30:
            print("血量过低，使用回血药水！")
            pyautogui.press('1')  # 按快捷键使用药水
        
        time.sleep(0.5)
```
