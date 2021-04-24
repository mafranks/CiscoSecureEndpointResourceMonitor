import PySimpleGUI as sg

WINDOW_SIZE = (1000, 700)
BUTTON_SIZE = (15, 1)
BUTTON_COLOR = ("Black", "Light Gray")
BAR_SIZE = (20, 20)
BAR_MAX = 100
DRC_Size = (5, 1)
Info_Txt_Size = (15, 1)
Checkbox_Size = (15, 1)
Proc_Info_Size = (60, 1)
Us = 60
val = 0
sg.theme('SystemDefault')

left_col = [
    [sg.Frame(layout=[
        [sg.Button("Start", size=BUTTON_SIZE, button_color=BUTTON_COLOR),
         sg.Button("Stop", size=BUTTON_SIZE, button_color=BUTTON_COLOR, disabled=True)],
        [sg.Text("")],
        [sg.Text("Engines Enabled")],
        [sg.Checkbox("File Scan", size=Checkbox_Size), sg.Checkbox("Network Scan")],
        [sg.Checkbox("MAP", size=Checkbox_Size, tooltip="Malicious Activity Protection"),
         sg.Checkbox("Script Protection")],
        [sg.Checkbox("SPP", size=Checkbox_Size, tooltip="System Process Protection"), sg.Checkbox("Exploit Prevention")],
        [sg.Checkbox("Script Control", size=Checkbox_Size), sg.Checkbox("Behavioral Protection")],
        [sg.Checkbox("TETRA")],
        [sg.Frame(layout=[
            [sg.Text("Disk", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_DISK")],
            [sg.Text("RAM", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_RAM")],
            [sg.Text("CPU", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_CPU")]
        ], title="Secure Endpoint Total Resources Used")],
    ], title="Resource Usage Test")]]

right_col = [
    [sg.Frame(layout=[
        [sg.Text("Path", size=Info_Txt_Size), sg.Text("_"*Us, key="_UI_PATH", size=Proc_Info_Size)],
        [sg.Text("Policy", size=Info_Txt_Size), sg.Text("_"*Us, key="_UI_POLICY", size=Proc_Info_Size)],
        [sg.Text("RAM Usage", size=Info_Txt_Size), sg.Text("_"*Us, key="_UI_RAM", size=Proc_Info_Size)],
        [sg.Text("RAM Usage Max", size=Info_Txt_Size), sg.Text("_"*Us, key="_UI_MAX_RAM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size), sg.Text("_"*Us, key="_UI_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size), sg.Text("_"*Us, key="_UI_MAX_CPU", size=Proc_Info_Size)],
    ], title="User Interface Process Info")],
    [sg.Frame(layout=[
        [sg.Text("Path", size=Info_Txt_Size), sg.Text("_"*Us, key="_SCAN_PATH", size=Proc_Info_Size)],
        [sg.Text("Version", size=Info_Txt_Size), sg.Text("_"*Us, key="_SCAN_VERSION", size=Proc_Info_Size)],
        [sg.Text("RAM Usage", size=Info_Txt_Size), sg.Text("_"*Us, key="_SCAN_RAM", size=Proc_Info_Size)],
        [sg.Text("RAM Usage Max", size=Info_Txt_Size), sg.Text("_"*Us, key="_SCAN_MAX_RAM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size), sg.Text("_"*Us, key="_SCAN_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size), sg.Text("_"*Us, key="_SCAN_MAX_CPU", size=Proc_Info_Size)],
    ], title="Scanner Process Info")]
]

layout = [
    [sg.Text("CISCO SECURE ENDPOINT RESOURCE MONITOR", text_color="black", justification="center",
             relief=sg.RELIEF_RIDGE, size=(51, 1), background_color="light blue", font=("Helvetica", 25))],
    [sg.Text("")],
    [sg.Text("Press Start to Begin", size=(88, 1), justification="center", font=("Helvetica", 15),
             border_width=1, relief=sg.RELIEF_RIDGE, background_color="white", text_color="black")],
    [sg.HSeparator()],
    [sg.Text("")],
    [sg.Column(left_col, element_justification='c'), sg.Column(right_col, element_justification='c')],
    [sg.HSeparator()],
    [sg.Text("")],
    [sg.Frame(layout=[
        [sg.Text("Version & Build", size=Checkbox_Size), sg.Text("_"*Us, key="_VERS_BUILD")],
        [sg.Text("Policy", size=Checkbox_Size), sg.Text("_"*Us, key="_POLICY")],
        [sg.Text("Policy Serial", size=Checkbox_Size), sg.Text("_"*Us, key="_POLICY_SERIAL")],
        [sg.Text("TETRA Version", size=Checkbox_Size), sg.Text("_"*Us, key="_TETRA")]
    ], title="Secure Endpoint Details")]

]

window = sg.Window("Cisco Secure Endpoint Resource Monitor 1.0.0 - Cisco Systems, Inc",
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
