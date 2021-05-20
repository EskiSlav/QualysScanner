import json
import logging
from random import choice, randint
from sys import stdout
from threading import Thread
from time import sleep
from typing import Any

from tqdm import tqdm

stdouth = logging.StreamHandler(stdout)
stdouth.setFormatter(logging.Formatter('%(message)s'))
fileh = logging.FileHandler('log.log', 'w')
fileh.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
logging.basicConfig(level=logging.INFO, handlers=[fileh, stdouth])

class Vulnerability:
    def __init__(self, code, description) -> None:
        self.code = code
        self.description = description
    
    def __str__(self):
        return f"   Code: {self.code} - {self.description[:50]}..."


class Module():
    def __init__(self, name) -> None:
        self.name = name

    def get_response(self):
        while True:
            for i, response in enumerate(responses_queue):
                if response.ancestor is self and response.type == 'response':
                    logging.debug(f'Got response with data: {response.data}')
                    return responses_queue.pop(i)
            sleep(0.5)


class Task:
    def __init__(self, name: str, ancestor: Module, type: str=None, data=None) -> None:
        self.name = name
        self.ancestor = ancestor
        self.type = type
        self.data = data

class Request(Task):
    def __init__(self, name: str, ancestor: Module, data=None) -> None:
        super().__init__(name, ancestor, 'request', data)

class Response(Task):
    def __init__(self, name: str, ancestor: Module, data) -> None:
        super().__init__(name, ancestor, 'response', data)
        

requests_queue: list[Request] = []
responses_queue: list[Response] = []

class Asset:
    def __init__(self, name: str, ip_addr: str) -> None:
        self.name = name
        self.ip_addr = ip_addr
        self.vulnerabilities : list[Vulnerability] = []

    def get_name(self) -> str:
        return self.name

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

    def __str__(self):
        return f" {self.name} - {self.ip_addr}"
        # return self.toJSON()    

class Report:
    def __init__(self, asset: Asset=None) -> None:
        self.name = asset.name
        self.asset: Asset = asset
    
    def __str__(self):
        s = f"Report for {self.name}:\n - IP: {self.asset.ip_addr}\n - Vulnerabilities:\n"
        for vulnerability in self.asset.vulnerabilities:
            s += f"  {vulnerability}\n"
        return s[:-1]


class User:
    def __init__(self, login: str, password: str, json=None) -> None:
        self.login = login
        self.password = password
        self.authenticated = False
    
    def toJSON(self):
        return json.loads(json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4))

    def __str__(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)    
        

class DataSystem(Module):
    def __init__(self) -> None:
        super().__init__('DataSystem')
        self.stop_thread = False
        self.assets : list[Asset] = [] 
        self.users : list[User] = []
        self.reports : list[Report] = []
        self.request_process_thread = Thread(target=self.serve_queue)
        self.request_process_thread.start()
        self.init_db()

    def init_db(self):
        self.users.append(User('Eski', 'Slav'))
        self.assets.append(Asset('Chef Computer', "192.168.1.100"))
        self.assets.append(Asset('My Computer', "192.168.1.200"))
        self.assets.append(Asset('Router', "192.168.1.1"))

    def register_user(self, usr: User) -> int:
        self.users.append(usr)
        return 0

    def get_user(self, login) -> User:
        for usr in self.users:
            if usr.login == login:
                return usr
        else:
            return None

    def get_asset(self, asset_name: str) -> Asset:
        for asset in self.assets:
            if asset.name == asset_name:
                return asset 
        return None
    
    def save_report(self, report: Report) -> int:
        self.reports.append(report)
        return 0

    def add_asset(self, asset_name: str, asset_ip: str) -> int:
        try:
            self.assets.append(Asset(asset_name, asset_ip))
        except Exception as e:
            logging.error(e)
            return 1
        return 0

    def is_user_exist(self, login: str) -> bool:
        if login in [user.get_login() for user in self.users]:
            return True
        return False

    def is_asset_exist(self, asset_name: str) -> bool:
        if asset_name in [asset.get_name() for asset in self.assets]:
            return True
        return False

    def get_list_of_assets(self):
        return self.assets

    def update_asset(self,**kwargs) -> int:
        for i, asset in enumerate(self.assets):
            if asset.name == kwargs['asset_name']:
                asset_to_update_index = i
                break
        try:
            self.assets[asset_to_update_index].vulnerabilities += kwargs['vulnerabilities']
            logging.debug(f"Updated asset {kwargs['asset_name']} vulnerabilities")
        except KeyError:
            pass
        try:
            self.assets[asset_to_update_index].ip_addr = kwargs['ip_addr']
            logging.debug(f"Updated asset {kwargs['asset_name']} IP address")
        except KeyError:
            pass

        return 0
    
    def update_user(self, usr):
        for i, user in enumerate(self.users):
            if user.login == usr.login:
                self.users[i] = usr

    def process_queue_task(self, request: Request) -> Response:
        logging.debug(f"Got {request.name} request")
        if request.name == 'get_user':
            usr = self.get_user(request.data['login'])
            self.send_response(request, {"user": usr})
        elif request.name == 'register_user':
            usr = User(request.data['login'], request.data['password'])
            self.register_user(usr)
            self.send_response(request, {'status': 0})
        elif request.name == 'get_list_of_assets':
            self.send_response(request, self.get_list_of_assets())
        elif request.name == 'add_asset':
            ret = self.add_asset(request.data['asset_name'], request.data['asset_ip'])
            self.send_response(request, {'status': ret})
        elif request.name == 'check_asset':
            ret = self.is_asset_exist(request.data['asset_name'])
            self.send_response(request, {'status': ret})
        elif request.name == 'send_results':
            ret = self.update_asset(**request.data)
            self.send_response(request, {'status': ret})
        elif request.name == 'get_asset':
            asset = self.get_asset(request.data['asset_name'])
            self.send_response(request, {'asset': asset})
        elif request.name == 'save_report':
            ret = self.save_report(request.data['report'])
            self.send_response(request, {'status': ret})
        elif request.name == 'update_user':
            ret = self.update_user(request.data['user'])
            self.send_response(request, {'status': ret})
        else:
            logging.warning('Unknown Request name')
            self.send_response(request, {'status': 1})

    def send_response(self, request: Request, data: Any):
        response = Response(request.name, request.ancestor, data)
        responses_queue.append(response)
        return 0

    def serve_queue(self):
        # self.db = connect('db.db')          
        while not self.stop_thread:
            sleep(0.3)
            if len(requests_queue) > 0:
                self.process_queue_task(requests_queue.pop(0))

class VulnerabilityScaner(Module):
    def __init__(self) -> None:
        super().__init__('VulnerabilityScaner')
        self.vulnerabilities_list: list[Vulnerability] = []
        self.load_vulnerabilities()

    def load_vulnerabilities(self):
        logging.debug('Loading Vulnerabilities list...')
        vulnerabilities = open('known_vulnerabilities.txt',  'r').readlines()
        for vulnerability in vulnerabilities:
            self.vulnerabilities_list.append(Vulnerability(*(vulnerability.split('---'))))
        logging.info('Vulnearabilities loaded')
        # self.list_vulnerabilities()

    def scan(self) -> None:
        asset_name = input("Asset name: ")
        self.check_asset(asset_name)
        found_vulnerabilities : list[Vulnerability] = [] 
        for i in tqdm(range(5)):
            sleep(0.3)
            if randint(0,1):
                found_vulnerabilities.append(choice(self.vulnerabilities_list))
        logging.info(f'Found {len(found_vulnerabilities)} vulnerabilities')
        print("Found next vulnerabilities:")
        for vulnerability in found_vulnerabilities:
            print("", vulnerability)

        if not self.send_results(asset_name, found_vulnerabilities):
            print('Results saved successfully')

    def list_vulnerabilities(self):
        for vulnerability in self.vulnerabilities_list:
            print(vulnerability)

    def send_results(self, asset_name, vulnerabilities) -> int:
        data = {'asset_name': asset_name, 'vulnerabilities': vulnerabilities}
        requests_queue.append(Request('send_results', self, data=data))
        logging.debug(f'Send scanning results of \'{asset_name}\'')
        response = self.get_response()
        return response.data['status']

    def check_asset(self, asset_name=None) -> str:
        if asset_name is None:
            asset_name = input("Asset name: ")
        requests_queue.append(Request('check_asset', self, data={'asset_name': asset_name}))
        response = self.get_response()
        print(f"Asset {asset_name} exists.")
        return response.data['status']


class AuthenticationSystem(Module):
    def __init__(self) -> None:
        super().__init__('AuthenticationSystem')

    def get_user(self, login=None, password=None) -> User:
        requests_queue.append(Request('get_user', self, data={"login" : login}))
        response = self.get_response()
        if response.data['user'] == None:
            return None
        if isinstance(response.data['user'], User):
            return response.data['user']

    def login_user(self, usr: User) -> None:
        logging.debug(f'User {usr.login} logging')
        db_user = self.get_user(usr.login)
        if not db_user:
            self.register_user(usr)
            self.login_user(usr)
        elif db_user.login == usr.login and db_user.password == usr.password:
            usr.authenticated = True
            requests_queue.append(Request('update_user', self, data={'user': usr}))
            response = self.get_response()
            logging.info(f"User '{usr.login}' authenticated")
        else:
            print("Invalid Credentials")

    def register_user(self, usr: User) -> None:
        requests_queue.append(Request('register_user', self, usr.toJSON()))
        response = self.get_response()
        if response.type == 'response' and response.data['status'] == 0:
            logging.info(f'User {usr.login} has been registered')
            return 0
        else:
            logging.error(f'User {usr.login} was not registered for some reason')
            return 1

    def log_out(self, usr: User):
        usr.authenticated = False
        requests_queue.append(Request('update_user', self, data={'user': usr}))
        response = self.get_response()
        if not response.data['status']:
            print("User logged out")
        else:
            logging.error(f"While updating user got error {response.data['status']}")
        

class ReportGenerator(Module):
    last_report: Report = None
    def __init__(self) -> None:
        super().__init__('ReportGenerator')

    def generate_report(self, asset_name: str=None) -> Report:
        if asset_name is None:
            asset_name = input("Asset name: ")
        requests_queue.append(Request('get_asset', self, data={'asset_name': asset_name}))
        response = self.get_response()
        asset: Asset = response.data['asset']
        return Report(asset)

    def save_report(self, report: Report):
        logging.info(f'Saving report {report.name}')
        requests_queue.append(Request('save_report', self, data={'report': report}))
        response = self.get_response()
        if not response.data['status']:
            print("Report Saved successfully")
        else:
            print(f"While saving reports got error {response.data['status']}")

    def check_asset(self, asset_name=None) -> str:
        if asset_name is None:
            asset_name = input("Asset name: ")
        requests_queue.append(Request('check_asset', self, data={'asset_name': asset_name}))
        response = self.get_response()
        print(f"Asset {asset_name} exists.")
        return response.data['status']


class AssetView(Module):
    def __init__(self) -> None:
        super().__init__('AssetView')

    def get_list_of_assets(self) -> list[Asset]:
        requests_queue.append(Request('get_list_of_assets', self))
        response = self.get_response()
        return response.data

    def add_asset(self):
        asset_name = input("Asset name: ")
        asset_ip = input("Asset ip: ")
        data = {"asset_name": asset_name, "asset_ip": asset_ip}
        requests_queue.append(Request('add_asset', self, data=data))
        response = self.get_response()

    def list_assets(self) -> None:
        print("Assets:")
        for asset in self.get_list_of_assets():
            print(" ", asset)


class QualysCloud:
    def __init__(self) -> None:
        self.authentication = AuthenticationSystem()
        self.asset_view = AssetView()
        self.report_generator = ReportGenerator()
        self.vulnerability_scanner = VulnerabilityScaner()
        self.data_system = DataSystem()

    def asset_view_menu(self):
        stop = False
        while not stop:
            print(
                "1. List All Assets\n" 
                "2. Add new asset\n"
                "3. Exit\n"
            )
            answer = input('Input: ')
            if answer == '1':
                self.asset_view.list_assets()
            elif answer == '2':
                self.asset_view.add_asset()
            elif answer == '3':
                stop = True
            else:
                print('Invalid number')
    
    def report_generator_menu(self):
        stop = False
        while not stop:
            print(
                "1. Check Asset\n" 
                "2. Generate Report for an asset\n"
                "3. Exit"
            )
            answer = input('Input: ')
            if answer == '1':
                self.report_generator.check_asset()
            elif answer == '2':
                report = self.report_generator.generate_report()
                print(report)
                self.report_generator.save_report(report)
            elif answer == '3':
                stop = True
            else:
                print('Invalid number')
    
    def vulnerability_scanner_menu(self):
        stop = False
        while not stop:
            print(
                "1. Check Asset\n" 
                "2. Scan Asset\n"
                "3. Exit\n"
            )
            answer = input('Input: ')
            if answer == '1':
                self.vulnerability_scanner.check_asset()
            elif answer == '2':
                self.vulnerability_scanner.scan()
            elif answer == '3':
                stop = True
            else:
                print('Invalid number')
    
    def user_interation(self, usr: User):
        stop = False
        while not stop:
            print(
                "1. Asset View\n" 
                "2. Repport Generator\n"
                "3. Vulnerability Scanner\n"
                "4. Log Out"
            )
            answer = input('Input: ')
            if answer == '1':
                self.asset_view_menu()
            elif answer == '2':
                self.report_generator_menu()
            elif answer == '3':
                self.vulnerability_scanner_menu()
            elif answer == '4':
                self.authentication.log_out(usr)
                stop = True
                self.data_system.stop_thread = True
            else:
                logging.info('Wrong number typed')

                        

def main():
    usr = User('EskiSlav', 'NiceLittlePassword')
    qualys = QualysCloud()
    qualys.authentication.login_user(usr)
    qualys.user_interation(usr)

if __name__ == '__main__':
    main()
