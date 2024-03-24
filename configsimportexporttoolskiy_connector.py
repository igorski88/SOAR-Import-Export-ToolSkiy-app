#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals


# Phantom App imports
import phantom.app as phantom
from phantom import vault 
from phantom.vault import Vault
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from configsimportexporttoolskiy_consts import *
from utils import convert_workbook_into_importable_JSON
import requests
import json
from bs4 import BeautifulSoup
import base64
from datetime import datetime


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class ConfigsImportExportToolskiyConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(ConfigsImportExportToolskiyConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = ConfigsImportExportToolskiyConnector._get_phantom_base_url()

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})


        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint
        
            
        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)
    
    def _handle_import(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        success_response_msg = ""
        
        #Get the files from the vault
        RAW_JSONdata = self.get_json_from_file(action_result)

        action_result.add_data({"RAW_JSONdata": RAW_JSONdata})
        
        success_response_msg = "Import Success"
        return action_result.set_status(phantom.APP_SUCCESS, success_response_msg)

    
    def _handle_export_workbooks(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        success_response_msg = ""

        #Grab all the Available workbook template names and IDs first
        Cmd = "/rest/workbook_template?page_size=0" # page zero indicates all pages Refrence: https://docs.splunk.com/Documentation/SOARonprem/6.1.1/PlatformAPI/RESTQueryData

        self.save_progress("Making Rest Call")
        # make rest call
        ret_val, response = self._make_rest_call(
            Cmd, action_result, params=None, headers=None
        )
        
        # get the Workbooks config
        Workbooks = {
                    "ret_val": ret_val,
                    "response": response                    
                }
        
        # get the asset config
        data_item = {
                    "workbooks_general_info": Workbooks                                    
                }
        
        action_result.add_data(data_item)        
            
        #action_result.update_summary({"parameter_selected": param["Items to Export"]})       
        

        if phantom.is_fail(ret_val):
            self.save_progress("Failed make Rest Call to get all the Workbook IDs.")
            return action_result.get_status()
        
        all_data_combined = []
        if response:
            if response['count'] == 0:
                return action_result.set_status(phantom.APP_ERROR, "Something went wrong getting all the available workbook templates.")

            else:
                action_result.update_summary({"Num_of_Workbooks_Found": response['count']})   
                Workbook_list = [item for item in response['data']]
                id_list = [item['id'] for item in response['data']] #Get a list of all availble IDs
                name_list = [item['name'] for item in response['data']]
                action_result.update_summary({"Workbooks_Detected": Workbook_list})

                for worbook in Workbook_list:
                    #print(f"Imported Workbook template: {worbook['name']}")
                                         
                    formated_response = self.RequestSingleWorkbook(action_result, worbook['id'], worbook) 
                    all_data_combined.append(formated_response)

                action_result.add_data({"Final_data_to_export_to_file": all_data_combined})
                
                # Get the current date
                current_date = datetime.now()

                # Format the date in a file-name-friendly format (e.g., YYYY-MM-DD)
                date_str_for_filename = current_date.strftime("%Y-%m-%d")
                
                FileName = f"workbook_templates_export - {len(id_list)} workbooks exported - {date_str_for_filename}"
                
                item_type = "workbook"
                  
                is_file_created = self.create_file(param, all_data_combined, FileName, ".json", item_type) #Last perameter is file type

                
                if is_file_created:
                    action_result.update_summary({"Files_Successfully_Created": {"File_Name": FileName}})
                    success_response_msg = "Found & exported " + str(len(id_list)) + " Workbooks. Check Files in this container."
                    return action_result.set_status(phantom.APP_SUCCESS, success_response_msg)
                else:
                    action_result.update_summary({"Files_Failed_To_Create": {"File_Name": FileName}})
                    return action_result.set_status(phantom.APP_ERROR, "Something went wrong creating the file")
   

    
    def RequestSingleWorkbook(self, action_result, WB_Template_ID, WB_Data):
        
        Cmd = f"/rest/workbook_phase_template?_filter_template={WB_Template_ID}"
        
        # make rest call
        ret_val, response = self._make_rest_call(
            Cmd, action_result, params=None, headers=None
        )
            
        
        if phantom.is_fail(ret_val):
            self.save_progress("Failed make Rest Call to get a Workbook IDs detailed data.")
            return action_result.get_status()
        
        if response:
            if response['count'] == 0:
                print(f"Something went wrong. Try confirming that the workbook ID exists") 

            else:           

                #Create the File name
                if WB_Data:                
                    WB_Template_Name = WB_Data['name']
                    WB_Template_isdefault = WB_Data['is_default']
                    WB_Template_Description = WB_Data['description']
                    WB_Template_isnoterequired = WB_Data['is_note_required']

                    #FileName = f"workbook_template_export - {WB_Template_Name}"                
                else: #When the function is called and only the ID is known
                    #if no name exists then go grab one
                    Cmd = f"workbook_template?_filter_id={WB_Template_ID}"                 
                    #api_url = f"https://{username}:{password}@{host}/rest/{Cmd}" # Construct the url for what we are looking for
                    #get_workbookinfo = (get_data(api_url)).json() # Making the GET request
                    #print(f"Raw Data: {get_workbookinfo['data']}")
                    #print(f"Raw Data: {response['data']}")
                    #WB_Template_Name = get_workbookinfo['data'][0]['name']
                    #WB_Template_isdefault = get_workbookinfo['data'][0]['is_default']
                    #WB_Template_Description = get_workbookinfo['data'][0]['description']
                    #WB_Template_isnoterequired = get_workbookinfo['data'][0]['is_note_required']
                    #FileName = f"workbook_template_export - {WB_Template_Name}"

                success_response_msg = f"{response['count']} Phases where exported from WorkBook ID: {WB_Template_ID} -- Name: {WB_Template_Name}"
                
                action_result.update_summary({f"Success_RequestSingleWorkbook_{WB_Data['id']}": success_response_msg})
                
                # Add 'name' and is_default to the begining of the json to store
                formated_response = {'name': WB_Template_Name, 
                    'is_default': WB_Template_isdefault, 
                    'description': WB_Template_Description, 
                    'is_note_required': WB_Template_isnoterequired,
                    'file_location': Vault.get_vault_tmp_dir(),
                    **response}

                data_item = {
                    "workbook_data": formated_response                                    
                }
                
                action_result.add_data(data_item) 
                
        # Return success
        self.save_progress(success_response_msg)
        return formated_response

    def create_file(self, action_result, data, file_name, file_type, item_type):
        #wrap the data in a parent JSON used to identify the type of data when importing
        app_json = self.get_app_json()
        
        wrapped_data = {
                    "item_type": item_type,
                    "file_name": file_name,
                    "date_time_exported": str(datetime.now()),
                    "export_environment_base_URL": self._base_url,
                    "export_environment_Splunk_SOAR_product_id": self.get_product_installation_id(),
                    "app_version": app_json["app_version"],
                    "data": data        
                }

        # Convert the Python dictionary to a JSON string, then encode it to bytes
        json_bytes = json.dumps(wrapped_data).encode('utf-8')
        container_id = self.get_container_id()
        resp = Vault.create_attachment(json_bytes, container_id, file_name, metadata=None)
        return resp.get("succeeded")

    def get_json_from_file(self, action_result):

        container_id = self.get_container_id()
        vault_info_success, vault_info_message, vault_info_data = vault.vault_info(vault_id=None, file_name=None, container_id=container_id, trace=True)
        action_result.add_data({"vault_info_success": vault_info_success, "vault_info_message": vault_info_message, "vault_info_data": vault_info_data})
        action_result.add_data({"path": vault_info_data[0]["path"]})
        
        RAW_JSONdata = ""
        with open(f'{vault_info_data[0]["path"]}', 'r') as raw_file:
            #Parse the JSON data into a Python dictionary
            RAW_JSONdata = json.load(raw_file)
            

        return RAW_JSONdata
 
    
    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            '/rest/system_info', action_result, params=None, headers=None
        )
        data_item = {
                    "Response": response,
                    "ret_val": ret_val
                }
        
        action_result.add_data(data_item)

        
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS, "Connectivity Test was Successful") 

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        #return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
            
        if action_id == 'export':
            if param["Items to Export"] == 'Workbooks':
                ret_val = self._handle_export_workbooks(param)
            
        if action_id == 'import':
            ret_val = self._handle_import(param)
        

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        # self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = ConfigsImportExportToolskiyConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = ConfigsImportExportToolskiyConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
