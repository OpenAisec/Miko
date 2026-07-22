"""
automation.py — 游戏自动化脚本模板

功能:
- 图像识别（模板匹配）
- 颜色检测
- 键鼠模拟
- 后台操作
- 任务编排

依赖:
    pip install pyautogui opencv-python pillow numpy pywin32
"""

import time
import ctypes
import ctypes.wintypes
from dataclasses import dataclass
from typing import Optional, Tuple

import cv2
import numpy as np
from PIL import ImageGrab
import pyautogui
import win32gui
import win32api
import win32con

# 安全设置
pyautogui.FAILSAFE = True
pyautogui.PAUSE = 0.05


# ========== 屏幕截图 ==========

def screenshot(region: Optional[Tuple[int, int, int, int]] = None) -> np.ndarray:
    """截取屏幕区域，返回 BGR 格式的 numpy 数组"""
    img = ImageGrab.grab(bbox=region)
    return cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)


# ========== 图像识别 ==========

@dataclass
class MatchResult:
    x: int
    y: int
    confidence: float


def find_template(
    template_path: str,
    region: Optional[Tuple[int, int, int, int]] = None,
    threshold: float = 0.8,
    method: int = cv2.TM_CCOEFF_NORMED
) -> Optional[MatchResult]:
    """在屏幕上查找模板图像"""
    screen = screenshot(region)
    template = cv2.imread(template_path)
    if template is None:
        print(f"[!] Template not found: {template_path}")
        return None

    result = cv2.matchTemplate(screen, template, method)
    _, max_val, _, max_loc = cv2.minMaxLoc(result)

    if max_val >= threshold:
        h, w = template.shape[:2]
        cx = max_loc[0] + w // 2
        cy = max_loc[1] + h // 2
        if region:
            cx += region[0]
            cy += region[1]
        return MatchResult(cx, cy, max_val)
    return None


def find_all_templates(
    template_path: str,
    region: Optional[Tuple[int, int, int, int]] = None,
    threshold: float = 0.8,
    min_distance: int = 10
) -> list[MatchResult]:
    """查找所有匹配位置"""
    screen = screenshot(region)
    template = cv2.imread(template_path)
    if template is None:
        return []

    result = cv2.matchTemplate(screen, template, cv2.TM_CCOEFF_NORMED)
    locations = np.where(result >= threshold)
    h, w = template.shape[:2]

    points = []
    for pt in zip(*locations[::-1]):
        cx = pt[0] + w // 2
        cy = pt[1] + h // 2
        if region:
            cx += region[0]
            cy += region[1]
        conf = result[pt[1], pt[0]]
        points.append(MatchResult(cx, cy, conf))

    # 去重: 合并距离过近的点
    merged = []
    used = [False] * len(points)
    for i, p in enumerate(points):
        if used[i]:
            continue
        cluster = [p]
        for j, q in enumerate(points):
            if i != j and not used[j]:
                if abs(p.x - q.x) < min_distance and abs(p.y - q.y) < min_distance:
                    cluster.append(q)
                    used[j] = True
        avg_x = int(np.mean([c.x for c in cluster]))
        avg_y = int(np.mean([c.y for c in cluster]))
        avg_c = max(c.confidence for c in cluster)
        merged.append(MatchResult(avg_x, avg_y, avg_c))
        used[i] = True

    return merged


def wait_for_template(
    template_path: str,
    timeout: float = 10.0,
    interval: float = 0.5,
    **kwargs
) -> Optional[MatchResult]:
    """等待模板出现"""
    start = time.time()
    while time.time() - start < timeout:
        result = find_template(template_path, **kwargs)
        if result:
            return result
        time.sleep(interval)
    return None


# ========== 颜色识别 ==========

def find_color(
    region: Tuple[int, int, int, int],
    target_rgb: Tuple[int, int, int],
    tolerance: int = 20
) -> Optional[Tuple[int, int]]:
    """在区域中查找指定颜色"""
    screen = screenshot(region)
    target_bgr = target_rgb[::-1]
    lower = np.array([max(0, c - tolerance) for c in target_bgr])
    upper = np.array([min(255, c + tolerance) for c in target_bgr])
    mask = cv2.inRange(screen, lower, upper)
    locations = np.where(mask > 0)
    if len(locations[0]) > 0:
        y, x = int(locations[0][0]), int(locations[1][0])
        return (x + region[0], y + region[1])
    return None


def get_color_at(x: int, y: int) -> Tuple[int, int, int]:
    """获取指定坐标的颜色 (RGB)"""
    img = ImageGrab.grab(bbox=(x, y, x + 1, y + 1))
    return img.getpixel((0, 0))


def measure_bar(
    region: Tuple[int, int, int, int],
    bar_color: Tuple[int, int, int],
    tolerance: int = 30
) -> float:
    """测量进度条百分比 (0-100)"""
    screen = screenshot(region)
    target_bgr = bar_color[::-1]
    lower = np.array([max(0, c - tolerance) for c in target_bgr])
    upper = np.array([min(255, c + tolerance) for c in target_bgr])
    mask = cv2.inRange(screen, lower, upper)
    col_filled = np.count_nonzero(np.count_nonzero(mask, axis=0))
    total_width = region[2] - region[0]
    return col_filled / total_width * 100 if total_width > 0 else 0


# ========== 键鼠操作 ==========

def click(x: int, y: int, button: str = 'left', delay: float = 0.05):
    """点击坐标"""
    pyautogui.click(x, y, button=button)
    time.sleep(delay)


def move_to(x: int, y: int, duration: float = 0.2):
    """移动鼠标"""
    pyautogui.moveTo(x, y, duration=duration)


def press_key(key: str, delay: float = 0.05):
    """按键"""
    pyautogui.press(key)
    time.sleep(delay)


def hotkey(*keys: str):
    """组合键"""
    pyautogui.hotkey(*keys)


def type_text(text: str, interval: float = 0.02):
    """输入文字"""
    pyautogui.typewrite(text, interval=interval)


# ========== 后台操作 ==========

def find_window(title: str) -> int:
    """查找窗口句柄"""
    hwnd = win32gui.FindWindow(None, title)
    return hwnd


def bg_click(hwnd: int, x: int, y: int, delay: float = 0.05):
    """后台点击（不激活窗口）"""
    lparam = win32api.MAKELONG(x, y)
    win32gui.PostMessage(hwnd, win32con.WM_LBUTTONDOWN, win32con.MK_LBUTTON, lparam)
    time.sleep(delay)
    win32gui.PostMessage(hwnd, win32con.WM_LBUTTONUP, 0, lparam)


def bg_key(hwnd: int, vk: int, delay: float = 0.05):
    """后台按键"""
    win32gui.PostMessage(hwnd, win32con.WM_KEYDOWN, vk, 0)
    time.sleep(delay)
    win32gui.PostMessage(hwnd, win32con.WM_KEYUP, vk, 0)


def get_window_rect(hwnd: int) -> Tuple[int, int, int, int]:
    """获取窗口矩形"""
    return win32gui.GetWindowRect(hwnd)


# ========== 任务编排 ==========

class TaskRunner:
    """自动化任务编排器"""

    def __init__(self):
        self.tasks: list[Tuple[str, callable]] = []
        self.running = False

    def add_task(self, name: str, func: callable):
        self.tasks.append((name, func))

    def run(self, loop: bool = False, loop_count: int = 1):
        self.running = True
        count = 0

        while self.running:
            count += 1
            print(f"\n=== Round {count} ===")

            for name, func in self.tasks:
                if not self.running:
                    break
                print(f"[>] {name}")
                try:
                    func()
                    print(f"[+] {name} done")
                except Exception as e:
                    print(f"[!] {name} failed: {e}")
                time.sleep(0.5)

            if not loop or (loop_count > 0 and count >= loop_count):
                break

        self.running = False

    def stop(self):
        self.running = False


# ========== 使用示例 ==========

def example_auto_battle():
    """自动战斗示例"""
    runner = TaskRunner()

    def find_enemy():
        pos = find_template('enemy_icon.png', threshold=0.7)
        if pos:
            click(pos.x, pos.y)
            time.sleep(0.5)

    def attack():
        press_key('space')
        time.sleep(1)

    def check_hp():
        hp = measure_bar((100, 50, 300, 70), (255, 0, 0))
        if hp < 30:
            press_key('1')  # 使用药水
            time.sleep(0.5)

    def check_battle_end():
        result = find_template('victory.png', threshold=0.8)
        if result:
            click(result.x, result.y)
            return True
        return False

    runner.add_task("找怪", find_enemy)
    runner.add_task("攻击", attack)
    runner.add_task("检查血量", check_hp)

    # 循环运行，直到战斗结束
    runner.run(loop=True, loop_count=100)


if __name__ == '__main__':
    print("automation.py loaded successfully")
    print("Functions: find_template, find_color, measure_bar, click, press_key, TaskRunner")
