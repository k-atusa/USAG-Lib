# test804 : capture
import time
import os
import pyautogui

# get mouse position
def get_mouse_pos(prompt_text):
    input(f"{prompt_text} (place mouse pointer and press ENTER)")
    pos = pyautogui.position()
    print(f" -> Position: ({pos.x}, {pos.y})")
    return pos.x, pos.y

# countdown before capture
def countdown():
    input("press ENTER to start capture")
    for i in range(3, 0, -1):
        print(f"{i} ", end="", flush=True)
        time.sleep(1)
    print()

# print mouse position
def show_mouse_position_realtime():
    print("Tracking current mouse position (Exit: Ctrl + C)")
    try:
        while True:
            x, y = pyautogui.position()
            print(f"\rPosition: ({x:4d}, {y:4d})", end="") # \r to overwrite
            time.sleep(0.1)
    except Exception:
        print("\nExiting program")

def main():
    print("=" * 40)
    print("1. Keyboard Macro")
    print("2. Mouse Macro")
    print("3. YLibrary Macro")
    print("4. Mouse Tracker")
    print("=" * 40)
    
    choice = input("Select Mode (1/2/3/4): ")
    if choice == '4':
        show_mouse_position_realtime()
        return
    if choice not in ['1', '2', '3']:
        print("Invalid input")
        return

    # setup capture area
    x0, y0 = get_mouse_pos("Left + Up of capture area")
    x1, y1 = get_mouse_pos("Right + Down of capture area")
    width, height = x1 - x0, y1 - y0
    print(f"-> Capture Area: ({x0}, {y0}) - ({x1}, {y1})")

    # setup capture number
    n = int(input("Numbers to capture: "))
    t = float(input("Waiting time after each capture (seconds): "))

    # setup next page button
    if choice == '2':
        x2, y2 = get_mouse_pos("Next page button")

    # setup next page key
    next_key = ""
    if choice == '1':
        next_key = input("Next page key (Ex. right, space, enter, pagedown): ")

    # countdown
    countdown()

    # start capture
    if choice == '1':
        for i in range(n):
            name = f"{SAVE_DIR}{i:04d}.png"
            pyautogui.screenshot(name, region=(x0, y0, width, height))
            print(name)
            pyautogui.press(next_key)
            time.sleep(t)
            
    elif choice == '2':
        for i in range(n):
            name = f"{SAVE_DIR}{i:04d}.png"
            pyautogui.screenshot(name, region=(x0, y0, width, height))
            print(name)
            pyautogui.moveTo(x0, y0, duration=0.6)
            time.sleep(0.2)
            pyautogui.moveTo(x2, y2, duration=0.6)
            pyautogui.click()
            time.sleep(t)
            
    elif choice == '3':
        num = 0
        count0 = n // 40
        count1 = n % 40
        
        def cap(pnum):
            nonlocal num
            for _ in range(pnum):
                name = f"{SAVE_DIR}{num:04d}.png"
                pyautogui.screenshot(name, region=(x0, y0, width, height))
                time.sleep(0.1)
                print(name)
                pyautogui.press("right")
                time.sleep(t)
                num += 1

        for _ in range(count0):
            cap(40)
            pyautogui.press("f5")
            print(" -> refreshed and waiting 20s...")
            time.sleep(20)
        cap(count1)

    # end capture
    print("\nExiting program")

SAVE_DIR = "./capture/"
os.makedirs(SAVE_DIR, exist_ok=True)
main()
