import PySimpleGUI as sg

WINDOW_SIZE = (1000, 700)
BUTTON_SIZE = (15, 1)
BUTTON_COLOR = ("Black", "Light Gray")
BAR_SIZE = (20, 20)
BAR_MAX = 100
val = 0
sg.theme('SystemDefault')

layout = [[
    [sg.Text("ANTIVIRUS RESOURCE MONITOR", text_color="black", justification="center",
             relief=sg.RELIEF_RIDGE, size=(51, 1), background_color="red", font=("Helvetica", 25))],
    [sg.Text("Press Start to Begin", size=(88, 1), justification="center", font=("Helvetica", 15),
             border_width=1, relief=sg.RELIEF_RIDGE, background_color="white", text_color="black")],
    [sg.Frame(layout=[
        [sg.Button("Start", size=BUTTON_SIZE, button_color=BUTTON_COLOR),
         sg.Button("Stop", size=BUTTON_SIZE, button_color=BUTTON_COLOR, disabled=True)],
        [sg.Checkbox("Run AV stress test in background")],
        [sg.Text("")],
        [sg.Frame(layout=[
            [sg.Text("Disk", size=(5, 1)), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_DISK")],
            [sg.Text("RAM", size=(5, 1)), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_RAM")],
            [sg.Text("CPU", size=(5, 1)), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_CPU")]
        ], title="Secure Endpoint Total Resources Used")]
    ], title="Resource Usage Test")]
]]

window = sg.Window("Cisco AV Resource Monitor 1.0.0 - Cisco Systems, Inc",
                   layout, size=WINDOW_SIZE, icon="images/cisco.ico")
while True:
    event, values = window.read()
    print(event, values)
    if event in (sg.WIN_CLOSED, "Exit"):
        break
    #remove this data holder before finalizing
    else:
        val += 10
        window['_DISK'].update(val)
        window['_RAM'].update(val)
        window['_CPU'].update(val)
window.close()
del window
