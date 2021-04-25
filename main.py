import PySimpleGUI as sg
import csv
import psutil
import xml.etree.ElementTree as ET
from pathlib import Path

WINDOW_SIZE = (1000, 760)
BUTTON_SIZE = (15, 1)
BUTTON_COLOR = ("Black", "Light Gray")
BAR_SIZE = (20, 20)
BAR_MAX = 100
DRC_Size = (5, 1)
Info_Txt_Size = (15, 1)
Checkbox_Size = (15, 1)
Proc_Info_Size = (60, 1)
Us = 60
path = r"C:/Program Files/Cisco/AMP"
sg.theme('SystemDefault')
max_disk = psutil.disk_usage("C:/").total // (2 ** 30)
amp_root_directory = Path(r'C:/Program Files/Cisco/AMP')
orbital_root_directory = Path(r'C:/Program Files/Cisco/Orbital')


def get_version():
    with open(f"{path}/installed_services.csv") as csvfile:
        csv_file = csv.reader(csvfile)
        for row in csv_file:
            if "Cisco AMP for Endpoints Connector" in row[0]:
                version = row[0].split(' ')[5]
                return version


def dig_thru_xml(*args, root, tag="{http://www.w3.org/2000/09/xmldsig#}", is_list=False):
    for arg in args[:-1]:
        query = "{}{}".format(tag, arg)
        root = root.findall(query)
        if root:
            root = root[0]
        else:
            return None
    root = root.findall("{}{}".format(tag, args[-1]))
    if root:
        if is_list:
            return [i.text for i in root]
        else:
            return root[0].text
    return None


def read_xmls(version, window):
    try:
        # Parse policy.xml
        with open(f"{path}/policy.xml") as infile:
            tree = ET.parse(infile)
            root = tree.getroot()

            policy_name = dig_thru_xml("Object", "config", "janus", "policy", "name", root=root)
            policy_serial = dig_thru_xml("Object", "config", "janus", "policy", "serial_number", root=root)
            policy_uuid = dig_thru_xml("Object", "config", "janus", "policy", "uuid", root=root)

            network = dig_thru_xml("Object", "config", "agent", "nfm", "enable", root=root)
            MAP = dig_thru_xml("Object", "config", "agent", "heuristic", "enable", root=root)
            script_protection = dig_thru_xml("Object", "config", "agent", "amsi", "enable", root=root)
            spp = dig_thru_xml("Object", "config", "agent", "driver", "selfprotect", "spp", root=root)
            exprev_enable = dig_thru_xml("Object", "config", "agent", "exprev", "enable", root=root)
            exprev_options = dig_thru_xml("Object", "config", "agent", "exprev", "v4", "options", root=root)
            behavioral_protection = dig_thru_xml("Object", "config", "agent", "apde", "enable", root=root)
            tetra = dig_thru_xml("Object", "config", "agent", "scansettings", "tetra", "enable", root=root)
            orbital_6_5_1_to_7_1_1 = dig_thru_xml("Object", "config", "orbital", "enable", root=root)
            orbital_7_1_1_to_7_1_5 = dig_thru_xml("Object", "config", "orbital", "enable_msi", root=root)
            orbital_7_1_5_plus = dig_thru_xml("Object", "config", "orbital", "enablemsi", root=root)
            if "1" in (orbital_6_5_1_to_7_1_1, orbital_7_1_1_to_7_1_5, orbital_7_1_5_plus):
                orbital = "1"

        # Parse global.xml
        with open(f"{path}/{version}/global.xml") as infile:
            tree = ET.parse(infile)
            root = tree.getroot()
            build = dig_thru_xml("Object", "config", "agent", "revision", root=root)

        # Parse local.xml
        with open(f"{path}/local.xml") as infile:
            tree = ET.parse(infile)
            root = tree.getroot()
            tetra_version = dig_thru_xml("agent", "engine", "tetra", "defversions", root=root, tag="").split(':')[1]

        if exprev_options in ("0x0000012B", "0x0000033B"):
            window["_SCRIPT_CONTROL"].update(True)
        window["_FILE_SCAN"].update(True)
        window["_NETWORK_SCAN"].update(network)
        window["_MAP"].update(MAP)
        window["_SCRIPT_PROTECTION"].update(script_protection)
        window["_SPP"].update(spp)
        window["_EXPLOIT_PREVENTION"].update(exprev_enable)
        window["_BEHAVIORAL_PROTECTION"].update(behavioral_protection)
        window["_TETRA"].update(tetra)
        window["_ORBITAL"].update(orbital)

        window["_SFC_PATH"].update(f"{path}/{version}/sfc.exe")
        window["_CSCM_PATH"].update(f"{path}/{version}/cscm.exe")
        window["_ORBITAL_PATH"].update(f"{'/'.join(path.split('/')[:3])}/Orbital/orbital.exe")

        window["_UI_POLICY"].update(policy_name)
        window["_VERS_BUILD"].update(f"{version}.{build}")
        window["_POLICY_UUID"].update(policy_uuid)
        window["_POLICY_SERIAL"].update(policy_serial)
        window["_TETRA_VERSION"].update(tetra_version)
        return window

    except Exception as e:
        exit(e)


left_col = [
    [sg.Frame(layout=[
        [sg.Text("")],
        [sg.Button("Start", size=BUTTON_SIZE, button_color=BUTTON_COLOR, key="_START"),
         sg.Button("Stop", size=BUTTON_SIZE, button_color=BUTTON_COLOR, disabled=True, key="_STOP")],
        [sg.Text("")],
        [sg.Text("Engines Enabled")],
        [sg.Checkbox("File Scan", size=Checkbox_Size, key="_FILE_SCAN"),
         sg.Checkbox("Network Scan", key="_NETWORK_SCAN")],
        [sg.Checkbox("MAP", size=Checkbox_Size, key="_MAP", tooltip="Malicious Activity Protection"),
         sg.Checkbox("Script Protection", key="_SCRIPT_PROTECTION")],
        [sg.Checkbox("SPP", size=Checkbox_Size, key="_SPP", tooltip="System Process Protection"),
         sg.Checkbox("Exploit Prevention", key="_EXPLOIT_PREVENTION")],
        [sg.Checkbox("Script Control", size=Checkbox_Size, key="_SCRIPT_CONTROL"),
         sg.Checkbox("Behavioral Protection", key="_BEHAVIORAL_PROTECTION")],
        [sg.Checkbox("TETRA", key="_TETRA", size=Checkbox_Size),
         sg.Checkbox("Orbital", key="_ORBITAL")],
        [sg.Text("")],
        [sg.Frame(layout=[
            [sg.Text("RAM", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_RAM")],
            [sg.Text("CPU", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_CPU")],
            [sg.Text("DISK", size=DRC_Size), sg.Text("0 MB", size=(20, 1), key="_DISK")]
        ], title="Secure Endpoint Total Resources Used")],
    ], title="Resource Usage Test")]]

right_col = [
    [sg.Frame(layout=[
        [sg.Text("Process", size=Info_Txt_Size), sg.Text("_" * Us, key="_SFC_PATH", size=Proc_Info_Size)],
        [sg.Text("RAM Usage", size=Info_Txt_Size), sg.Text("_" * Us, key="_SFC_RAM", size=Proc_Info_Size)],
        [sg.Text("RAM Usage Max", size=Info_Txt_Size), sg.Text("_" * Us, key="_SFC_MAX_RAM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size), sg.Text("_" * Us, key="_SFC_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size), sg.Text("_" * Us, key="_SFC_MAX_CPU", size=Proc_Info_Size)],
        [sg.Text("Process", size=Info_Txt_Size), sg.Text("_" * Us, key="_CSCM_PATH", size=Proc_Info_Size)],
        [sg.Text("RAM Usage", size=Info_Txt_Size), sg.Text("_" * Us, key="_CSCM_RAM", size=Proc_Info_Size)],
        [sg.Text("RAM Usage Max", size=Info_Txt_Size), sg.Text("_" * Us, key="_CSCM_MAX_RAM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size), sg.Text("_" * Us, key="_CSCM_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size), sg.Text("_" * Us, key="_CSCM_MAX_CPU", size=Proc_Info_Size)],
        [sg.Text("Process", size=Info_Txt_Size), sg.Text("_" * Us, key="_ORBITAL_PATH", size=Proc_Info_Size)],
        [sg.Text("RAM Usage", size=Info_Txt_Size), sg.Text("_" * Us, key="_ORBITAL_RAM", size=Proc_Info_Size)],
        [sg.Text("RAM Usage Max", size=Info_Txt_Size), sg.Text("_" * Us, key="_ORBITAL_MAX_RAM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size), sg.Text("_" * Us, key="_ORBITAL_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size), sg.Text("_" * Us, key="_ORBITAL_MAX_CPU", size=Proc_Info_Size)],
    ], title="Processes")],
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
        [sg.Text("Version & Build", size=Checkbox_Size), sg.Text("_" * Us, key="_VERS_BUILD")],
        [sg.Text("Policy", size=Info_Txt_Size), sg.Text("_" * Us, key="_UI_POLICY", size=Proc_Info_Size)],
        [sg.Text("Policy UUID", size=Checkbox_Size), sg.Text("_" * Us, key="_POLICY_UUID")],
        [sg.Text("Policy Serial", size=Checkbox_Size), sg.Text("_" * Us, key="_POLICY_SERIAL")],
        [sg.Text("TETRA Version", size=Checkbox_Size), sg.Text("_" * Us, key="_TETRA_VERSION")]
    ], title="Secure Endpoint Details")]

]

window = sg.Window("Cisco Secure Endpoint Resource Monitor 1.0.0 - Cisco Systems, Inc",
                   layout, size=WINDOW_SIZE, icon="images/cisco.ico", resizable=True)
window.read(timeout=100)

version = get_version()
window = read_xmls(version, window)


def main(window):
    sfc_max_cpu, sfc_cpu, sfc_max_ram, sfc_ram, \
        cscm_max_cpu, cscm_cpu, cscm_max_ram, cscm_ram, \
        orbital_max_cpu, orbital_cpu, orbital_max_ram, orbital_ram, \
        total_ram, total_cpu, started = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    event, values = window.read()

    if event in (sg.WIN_CLOSED, "Exit"):
        window.close()
        del window
        exit()

    if event == "_START":
        window['_START'].update(disabled=True)
        window['_STOP'].update(disabled=False)
        started = 1
        while True:
            event, values = window.read(timeout=300)
            if event in (sg.WIN_CLOSED, "Exit"):
                window.close()
                del window
                exit()
            if event == "_STOP":
                window['_START'].update(disabled=False)
                window['_STOP'].update(disabled=True)
                started = 0
                window.read(timeout=10)
            if event == "_START":
                window['_START'].update(disabled=True)
                window['_STOP'].update(disabled=False)
                started = 1
                window.read(timeout=10)
            if started == 1:
                processes = [proc for proc in psutil.process_iter()]
                processors = psutil.cpu_count()
                for proc in processes:
                    if proc.name() == "sfc.exe":
                        try:
                            sfc_cpu = proc.cpu_percent()/processors
                            if sfc_cpu > sfc_max_cpu:
                                sfc_max_cpu = sfc_cpu
                            sfc_ram = proc.memory_percent()/processors
                            if sfc_ram > sfc_max_ram:
                                sfc_max_ram = sfc_ram
                        except ProcessLookupError as e:
                            print(e)
                    elif proc.name() == "cscm.exe":
                        try:
                            cscm_cpu = proc.cpu_percent()/processors
                            if cscm_cpu > cscm_max_cpu:
                                cscm_max_cpu = cscm_cpu
                            cscm_ram = proc.memory_percent()/processors
                            if cscm_ram > cscm_max_ram:
                                cscm_max_ram = cscm_ram
                        except ProcessLookupError as e:
                            print(e)
                    elif proc.name() == "orbital.exe":
                        try:
                            orbital_cpu = proc.cpu_percent()/processors
                            if orbital_cpu > orbital_max_cpu:
                                orbital_max_cpu = orbital_cpu
                            orbital_ram = proc.memory_percent()/processors
                            if orbital_ram > orbital_max_ram:
                                orbital_max_ram = orbital_ram
                        except ProcessLookupError as e:
                            print(e)
                total_ram = sfc_ram + cscm_ram + orbital_ram
                total_cpu = sfc_cpu + sfc_ram + orbital_ram
                try:
                    amp_disk_usage = sum(f.stat().st_size for f in amp_root_directory.glob('**/*') if f.is_file())
                    orbital_disk_usage = sum(f.stat().st_size for f in orbital_root_directory.glob('**/*') if f.is_file())
                    disk_usage = f"{(amp_disk_usage + orbital_disk_usage) / (2**20):.3f} MB"
                except PermissionError as e:
                    print(e)
                    disk_usage = "Permission Error.  Run as Admin."
                window['_SFC_RAM'].update(f"{sfc_ram:.4f} %")
                window['_SFC_CPU'].update(f"{sfc_cpu:.4f} %")
                window['_SFC_MAX_CPU'].update(f"{sfc_max_cpu:.4f} %")
                window['_SFC_MAX_RAM'].update(f"{sfc_max_ram:.4f} %")
                window['_CSCM_RAM'].update(f"{cscm_ram:.4f} %")
                window['_CSCM_CPU'].update(f"{cscm_cpu:.4f} %")
                window['_CSCM_MAX_CPU'].update(f"{cscm_max_cpu:.4f} %")
                window['_CSCM_MAX_RAM'].update(f"{cscm_max_ram:.4f} %")
                window['_ORBITAL_RAM'].update(f"{orbital_ram:.4f} %")
                window['_ORBITAL_CPU'].update(f"{orbital_cpu:.4f} %")
                window['_ORBITAL_MAX_CPU'].update(f"{orbital_max_cpu:.4f} %")
                window['_ORBITAL_MAX_RAM'].update(f"{orbital_max_ram:.4f} %")

                window['_DISK'].update(disk_usage)
                window['_RAM'].update(total_ram)
                window['_CPU'].update(total_cpu)


main(window)
