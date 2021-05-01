import os
import xml.etree.ElementTree as ET
from pathlib import Path
import logging
import re
try:
    import psutil
    import PySimpleGUI as sg
except ModuleNotFoundError as e:
    logging.info(f"Module not found. {e}")
    print(f"Module not found. {e}")


logging.basicConfig(
    format='%(asctime)s %(name)-12s %(levelname)-8s %(filename)s %(funcName)s %(message)s',
    datefmt='%m-%d %H:%M:%S',
    level=logging.INFO,
    filename="amp_resource_monitor.log"
)
logging.info(f"AMP Resource Montior is {logging.getLevelName(logging.getLogger().level)}")

WINDOW_SIZE = (940, 780)
BUTTON_SIZE = (15, 1)
BUTTON_COLOR = ("Black", "Light Gray")
TRUE_BC = ("Black", "Green")
FALSE_BC = ("Black", "Red")
BAR_SIZE = (20, 20)
BAR_MAX = 100
DRC_Size = (5, 1)
Info_Txt_Size = (15, 1)
Checkbox_Size = (17, 1)
Proc_Info_Size = (10, 1)
Path_Size = (50, 1)
Details_Size = (92, 1)
path = r"C:/Program Files/Cisco/AMP"
sg.theme('SystemDefault')
max_disk = psutil.disk_usage("C:/").total // (2 ** 30)
amp_root_directory = Path(r'C:/Program Files/Cisco/AMP')
orbital_root_directory = Path(r'C:/Program Files/Cisco/Orbital')


def get_version():
    """
    Pull the AMP version from the installed_services.csv file
    """
    logging.info("Starting get_version")
    directory = os.listdir(path)
    max_version = [0, 0, 0]
    reg_version = r'\d{1,2}\.\d{1,2}\.\d{1,2}'
    for entry in directory:
        reg = re.findall(reg_version, entry)
        if reg:
            if [int(x) for x in reg[0].split(".")] > max_version:
                max_version = list(map(lambda x: int(x), reg[0].split(".")))
    logging.info(f"Version found: {max_version}")
    return ".".join([str(x) for x in max_version])


def dig_thru_xml(*args, root, tag="{http://www.w3.org/2000/09/xmldsig#}", is_list=False):
    """
    Look through an XML file for a specific entry
    """
    logging.info("Digging through XML")
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
            logging.info("Returning list from XML")
            return [i.text for i in root]
        else:
            logging.info("Returning entry from XML")
            return root[0].text
    return None


def read_xmls(version, window):
    """
    Define information from local, global and policy XMLs
    """
    try:
        logging.info("Starting to process XMLs")
        with open(f"{path}/policy.xml") as infile:
            logging.info("Policy.xml is open")
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
            orbital = '0'
            if "1" in (orbital_6_5_1_to_7_1_1, orbital_7_1_1_to_7_1_5, orbital_7_1_5_plus):
                orbital = '1'
            logging.info("Closing policy.xml")

        with open(f"{path}/{version}/global.xml") as infile:
            logging.info("Global.xml is open")
            tree = ET.parse(infile)
            root = tree.getroot()
            build = dig_thru_xml("Object", "config", "agent", "revision", root=root)
            logging.info("Closing global.xml")

        with open(f"{path}/local.xml") as infile:
            logging.info("Local.xml is open")
            tree = ET.parse(infile)
            root = tree.getroot()
            tetra_version = dig_thru_xml("agent", "engine", "tetra", "defversions", root=root, tag="").split(':')[1]
            logging.info("Closing local.xml")

        logging.info("Updating window elements with values from XMLs")
        if exprev_options in ("0x0000012B", "0x0000033B"):
            window["_SCRIPT_CONTROL"].update(button_color=TRUE_BC)
        window["_FILE_SCAN"].update(button_color=TRUE_BC)
        if network == '1':
            window["_NETWORK_SCAN"].update(button_color=TRUE_BC)
        if MAP == '1':
            window["_MAP"].update(button_color=TRUE_BC)
        if script_protection == '1':
            window["_SCRIPT_PROTECTION"].update(button_color=TRUE_BC)
        if spp == '1':
            window["_SPP"].update(button_color=TRUE_BC)
        if exprev_enable == '1':
            window["_EXPLOIT_PREVENTION"].update(button_color=TRUE_BC)
        if behavioral_protection == '1':
            window["_BEHAVIORAL_PROTECTION"].update(button_color=TRUE_BC)
        if tetra == '1':
            window["_TETRA"].update(button_color=TRUE_BC)
        if orbital == '1':
            window["_ORBITAL"].update(button_color=TRUE_BC)

        window["_SFC_PATH"].update(f"{path}/{version}/sfc.exe")
        window["_CSCM_PATH"].update(f"{path}/{version}/cscm.exe")
        window["_ORBITAL_PATH"].update(f"{'/'.join(path.split('/')[:3])}/Orbital/orbital.exe")

        window["_UI_POLICY"].update(policy_name)
        window["_VERS_BUILD"].update(f"{version}.{build}")
        window["_POLICY_UUID"].update(policy_uuid)
        window["_POLICY_SERIAL"].update(policy_serial)
        window["_TETRA_VERSION"].update(tetra_version)
        logging.info("Window elements updated successfully")
        return window

    except Exception as e:
        logging.info(f"Exception hit:{e}")
        exit(e)


logging.info("Establishing window columns' layout")
left_col = [
    [sg.Frame(layout=[
        [sg.Text("")],
        [sg.Button("Start", size=BUTTON_SIZE, button_color=BUTTON_COLOR, key="_START"),
         sg.Button("Stop", size=BUTTON_SIZE, button_color=BUTTON_COLOR, disabled=True, key="_STOP")],
        [sg.Text("")],
        [sg.Text("Engines Enabled"), sg.Button(button_color=('black', 'green'), size=(3, 1)),
         sg.Text("Engines Disabled"), sg.Button(button_color=FALSE_BC, size=(3, 1))],
        [sg.Text("")],
        [sg.Button(button_text="File Scan", size=Checkbox_Size, key="_FILE_SCAN", button_color=FALSE_BC),
         sg.Button(button_text="Network Scan", key="_NETWORK_SCAN", size=Checkbox_Size, button_color=FALSE_BC)],
        [sg.Button("MAP", size=Checkbox_Size, key="_MAP", tooltip="Malicious Activity Protection",
                   button_color=FALSE_BC),
         sg.Button(button_text="Script Protection", key="_SCRIPT_PROTECTION", size=Checkbox_Size,
                   button_color=FALSE_BC)],
        [sg.Button(button_text="SPP", size=Checkbox_Size, key="_SPP", tooltip="System Process Protection"),
         sg.Button(button_text="Exploit Prevention", key="_EXPLOIT_PREVENTION", size=Checkbox_Size,
                   button_color=FALSE_BC)],
        [sg.Button(button_text="Script Control", size=Checkbox_Size, key="_SCRIPT_CONTROL", button_color=FALSE_BC),
         sg.Button(button_text="Behavioral Protection", key="_BEHAVIORAL_PROTECTION", size=Checkbox_Size,
                   button_color=FALSE_BC)],
        [sg.Button(button_text="TETRA", key="_TETRA", size=Checkbox_Size, button_color=FALSE_BC),
         sg.Button(button_text="Orbital", key="_ORBITAL", size=Checkbox_Size, button_color=FALSE_BC)],
        [sg.Text("")],
        [sg.Frame(layout=[
            [sg.Text("MEM", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_MEM")],
            [sg.Text("CPU", size=DRC_Size), sg.ProgressBar(BAR_MAX, orientation="h", size=BAR_SIZE, key="_CPU")],
            [sg.Text("DISK", size=DRC_Size), sg.Text("0 MB", size=(30, 1), key="_DISK")]
        ], title="Secure Endpoint Total Resources Used")],
    ], title="Resource Usage Test")]]

right_col = [
    [sg.Frame(layout=[
        [sg.Text("Process", size=Info_Txt_Size), sg.Text("", key="_SFC_PATH", size=Path_Size)],
        [sg.Text("MEM Usage", size=Info_Txt_Size),
         sg.Text("MEM%: ", size=DRC_Size), sg.Text("", key="_SFC_MEM", size=Proc_Info_Size)],
        [sg.Text("MEM Usage Max", size=Info_Txt_Size),
         sg.Text("MEM%: ", size=DRC_Size), sg.Text("", key="_SFC_MAX_MEM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size),
         sg.Text("CPU%: ", size=DRC_Size), sg.Text("", key="_SFC_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size),
         sg.Text("CPU%: ", size=DRC_Size), sg.Text("", key="_SFC_MAX_CPU", size=Proc_Info_Size)],
        [sg.Text("")],
        [sg.Text("Process", size=Info_Txt_Size), sg.Text("", key="_CSCM_PATH", size=Path_Size)],
        [sg.Text("MEM Usage", size=Info_Txt_Size),
         sg.Text("MEM%: ", size=DRC_Size), sg.Text("", key="_CSCM_MEM", size=Proc_Info_Size)],
        [sg.Text("MEM Usage Max", size=Info_Txt_Size),
         sg.Text("MEM%: ", size=DRC_Size), sg.Text("", key="_CSCM_MAX_MEM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size),
         sg.Text("CPU%: ", size=DRC_Size), sg.Text("", key="_CSCM_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size),
         sg.Text("CPU%: ", size=DRC_Size), sg.Text("", key="_CSCM_MAX_CPU", size=Proc_Info_Size)],
        [sg.Text("")],
        [sg.Text("Process", size=Info_Txt_Size), sg.Text("", key="_ORBITAL_PATH", size=Path_Size)],
        [sg.Text("MEM Usage", size=Info_Txt_Size),
         sg.Text("MEM%: ", size=DRC_Size), sg.Text("", key="_ORBITAL_MEM", size=Proc_Info_Size)],
        [sg.Text("MEM Usage Max", size=Info_Txt_Size),
         sg.Text("MEM%: ", size=DRC_Size), sg.Text("", key="_ORBITAL_MAX_MEM", size=Proc_Info_Size)],
        [sg.Text("CPU Usage", size=Info_Txt_Size),
         sg.Text("CPU%: ", size=DRC_Size), sg.Text("", key="_ORBITAL_CPU", size=Proc_Info_Size)],
        [sg.Text("CPU Usage Max", size=Info_Txt_Size),
         sg.Text("CPU%: ", size=DRC_Size), sg.Text("", key="_ORBITAL_MAX_CPU", size=Proc_Info_Size)],
    ], title="Processes")],
]

layout = [
    [sg.Text("CISCO SECURE ENDPOINT RESOURCE MONITOR", text_color="black", justification="center",
             relief=sg.RELIEF_RIDGE, size=(51, 1), background_color="light blue", font=("Helvetica", 25))],
    [sg.Text("Press Start to Begin", size=(88, 1), justification="center", font=("Helvetica", 15),
             border_width=1, relief=sg.RELIEF_RIDGE, background_color="white", text_color="black", key="_RUN_TEXT")],
    [sg.HSeparator()],
    [sg.Column(left_col, element_justification='c'), sg.Column(right_col, element_justification='c')],
    [sg.HSeparator()],
    [sg.Text("")],
    [sg.Frame(layout=[
        [sg.Text("Version & Build", size=Checkbox_Size), sg.Text("", key="_VERS_BUILD", size=Details_Size)],
        [sg.Text("Policy", size=Checkbox_Size), sg.Text("", key="_UI_POLICY", size=Details_Size)],
        [sg.Text("Policy UUID", size=Checkbox_Size), sg.Text("", key="_POLICY_UUID", size=Details_Size)],
        [sg.Text("Policy Serial", size=Checkbox_Size), sg.Text("", key="_POLICY_SERIAL", size=Details_Size)],
        [sg.Text("TETRA Version", size=Checkbox_Size), sg.Text("", key="_TETRA_VERSION", size=Details_Size)]
    ], title="Secure Endpoint Details")]
]
logging.info("Window columns established")

window = sg.Window("Cisco Secure Endpoint Resource Monitor 1.0.0 - Cisco Systems, Inc",
                   layout, size=WINDOW_SIZE, icon="images/cisco.ico", resizable=True)
window.read(timeout=100)
logging.info("Window object created")

version = get_version()
window = read_xmls(version, window)


class ProcessInfo:

    def __init__(self):
        self.sfc_max_cpu = 0
        self.sfc_cpu = 0
        self.sfc_max_mem = 0
        self.sfc_mem = 0
        self.cscm_max_cpu = 0
        self.cscm_cpu = 0
        self.cscm_max_mem = 0
        self.cscm_mem = 0
        self.orbital_max_cpu = 0
        self.orbital_cpu = 0
        self.orbital_max_mem = 0
        self.orbital_mem = 0
        self.total_mem = 0
        self.total_cpu = 0
        self.disk_usage = 0
        self.amp_disk_usage = 0
        self.orbital_disk_usage = 0

    def update(self, main_window):
        main_window['_SFC_MEM'].update(f"{self.sfc_mem:.4f} %")
        main_window['_SFC_CPU'].update(f"{self.sfc_cpu:.4f} %")
        main_window['_SFC_MAX_CPU'].update(f"{self.sfc_max_cpu:.4f} %")
        main_window['_SFC_MAX_MEM'].update(f"{self.sfc_max_mem:.4f} %")
        main_window['_CSCM_MEM'].update(f"{self.cscm_mem:.4f} %")
        main_window['_CSCM_CPU'].update(f"{self.cscm_cpu:.4f} %")
        main_window['_CSCM_MAX_CPU'].update(f"{self.cscm_max_cpu:.4f} %")
        main_window['_CSCM_MAX_MEM'].update(f"{self.cscm_max_mem:.4f} %")
        main_window['_ORBITAL_MEM'].update(f"{self.orbital_mem:.4f} %")
        main_window['_ORBITAL_CPU'].update(f"{self.orbital_cpu:.4f} %")
        main_window['_ORBITAL_MAX_CPU'].update(f"{self.orbital_max_cpu:.4f} %")
        main_window['_ORBITAL_MAX_MEM'].update(f"{self.orbital_max_mem:.4f} %")

        main_window['_DISK'].update(f"{self.disk_usage} MB")
        main_window['_MEM'].update(self.total_mem)
        main_window['_CPU'].update(self.total_cpu)
        return main_window

def main(main_window):

    logging.info("Starting main function")
    event, values = main_window.read()

    if event in (sg.WIN_CLOSED, "Exit"):
        logging.info("Window Close event received")
        main_window.close()
        del main_window
        exit()

    if event == "_START":
        logging.info("Start event received")
        main_window['_START'].update(disabled=True)
        main_window['_STOP'].update(disabled=False)
        data = ProcessInfo()
        main_window['_RUN_TEXT'].update("Running")
        started = 1
        while True:
            event, values = main_window.read(timeout=300)
            if event in (sg.WIN_CLOSED, "Exit"):
                logging.info("Window Close event received")
                main_window.close()
                del main_window
                exit()
            if event == "_STOP":
                logging.info("Stop event received")
                main_window['_START'].update(disabled=False)
                main_window['_STOP'].update(disabled=True)
                started = 0
                main_window['_RUN_TEXT'].update("Press Start to Continue")
                main_window.read(timeout=10)
            if event == "_START":
                logging.info("Start event received")
                main_window['_START'].update(disabled=True)
                main_window['_STOP'].update(disabled=False)
                data = ProcessInfo()
                main_window['_RUN_TEXT'].update("Running")
                main_window = data.update(main_window)
                main_window.read(timeout=10)
                started = 1
            if started == 1:
                logging.info("Gathering processes information")
                processes = [proc for proc in psutil.process_iter()]
                logging.info("Gathering processors information")
                processors = psutil.cpu_count()
                logging.info("Pull sfc, cscm and orbital information from processes")
                try:
                    for proc in processes:
                        if proc.name() == "sfc.exe":
                            try:
                                data.sfc_cpu = proc.cpu_percent()/processors
                                if data.sfc_cpu > data.sfc_max_cpu:
                                    data.sfc_max_cpu = data.sfc_cpu
                                data.sfc_mem = proc.memory_percent()/processors
                                if data.sfc_mem > data.sfc_max_mem:
                                    data.sfc_max_mem = data.sfc_mem
                            except (ProcessLookupError, AttributeError, psutil.NoSuchProcess) as e:
                                logging.info(f"Exception hit:{e}")
                        elif proc.name() == "cscm.exe":
                            try:
                                data.cscm_cpu = proc.cpu_percent()/processors
                                if data.cscm_cpu > data.cscm_max_cpu:
                                    data.cscm_max_cpu = data.cscm_cpu
                                data.cscm_mem = proc.memory_percent()/processors
                                if data.cscm_mem > data.cscm_max_mem:
                                    data.cscm_max_mem = data.cscm_mem
                            except (ProcessLookupError, AttributeError, psutil.NoSuchProcess) as e:
                                logging.info(f"Exception hit:{e}")
                        elif proc.name() == "orbital.exe":
                            try:
                                data.orbital_cpu = proc.cpu_percent()/processors
                                if data.orbital_cpu > data.orbital_max_cpu:
                                    data.orbital_max_cpu = data.orbital_cpu
                                data.orbital_mem = proc.memory_percent()/processors
                                if data.orbital_mem > data.orbital_max_mem:
                                    data.orbital_max_mem = data.orbital_mem
                            except (ProcessLookupError, AttributeError, psutil.NoSuchProcess) as e:
                                logging.info(f"Exception hit:{e}")
                except Exception as e:
                    logging.info(e)
                logging.info("Calculating total MEM and total CPU usage")
                data.total_mem = data.sfc_mem + data.cscm_mem + data.orbital_mem
                data.total_cpu = data.sfc_cpu + data.cscm_cpu + data.orbital_cpu
                try:
                    logging.info("Calculating AMP disk usage")
                    data.amp_disk_usage = sum(f.stat().st_size for f in amp_root_directory.glob('**/*') if f.is_file())
                    data.orbital_disk_usage = sum(f.stat().st_size
                                             for f in orbital_root_directory.glob('**/*') if f.is_file())
                    data.disk_usage = f"{(data.amp_disk_usage + data.orbital_disk_usage) / (2**20):.3f}"
                except (PermissionError, FileNotFoundError) as e:
                    logging.info(f"Exception hit:{e}")
                logging.info("Updating window information with MEM and CPU information")
                main_window = data.update(main_window)


main(window)
