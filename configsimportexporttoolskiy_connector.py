#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# App Connector python file.
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals


# Phantom App imports
import phantom.app as phantom
from phantom import vault 
from phantom.vault import Vault
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended.
#from configsimportexporttoolskiy_consts import *
from utils import convert_workbook_into_importable_JSON
from utils import is_valid_json_With_Values
import requests
import json
from bs4 import BeautifulSoup
import gzip
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
                phantom.APP_ERROR, "Empty response and no information in the header."
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
            error_text = "Cannot parse error details."

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
    
    def _process_gzip_response(self, r, action_result):
        
        # Try to decompress and parse the gzip content
        try:
            #decompressed_data = dir(r)
            decompressed_data = str(r.content)
            
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse gzip response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, decompressed_data)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            decompressed_data.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, "message"), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})
            
            #action_result.add_data({"Debug_Data": {"r_status_code": r.status_code, "r_text": r.text, "r_headers": r.headers}}) 
        


        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            action_result.add_data({"Raw_JSON": str(r.json())})
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)
        
        if 'gzip' in r.headers.get('Content-Type', ''):
            #action_result.add_data({"Raw_gzip_content": str(r.content)})
            #action_result.add_data({"r": str(r)})
            return self._process_gzip_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method, **kwargs):
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
        
        AllFiles_in_Vault = self.get_all_files_in_vault(action_result)
        
        if not AllFiles_in_Vault:
            return action_result.set_status(phantom.APP_ERROR, "No files in the file section of this container. Please upload files and try again.")

        action_result.update_summary({"files": AllFiles_in_Vault})
        
       
    
        if AllFiles_in_Vault:                    
            for _file in AllFiles_in_Vault:
                #print(f"You selected '{_file}' to be imported.")
                action_result.update_summary({_file["name"]: _file})

                #Get the files from the vault.
                RAW_JSONdata = self.get_json_from_file(action_result, _file["path"])
                action_result.add_data({"RAW_JSONdata": RAW_JSONdata})
                SearchKeyword = RAW_JSONdata["item_type"]
                response = ""
                
                if SearchKeyword == "workbook":
                    for raw_worbook in RAW_JSONdata["data"]:
                        formated_response = convert_workbook_into_importable_JSON(raw_worbook)
                        action_result.add_data({"Formated_Workbooks": {raw_worbook["name"]: formated_response}})
                        
                        data_wrapped = {"data": [formated_response]}
                        action_result.add_data({"data_wrapped": data_wrapped})
                        endpoint_path = "/rest/workbook_template"
                        response = self.post_data(action_result, endpoint_path, data_wrapped)
                
                elif SearchKeyword == "Users":
                    #TODO ###RAW_JSONdata["password"] = SelectedPassword #Passwords must have at least  8 total characters
                    endpoint_path = "/rest/ph_user"
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)
                
                elif SearchKeyword == "Roles":
                    endpoint_path = "/rest/role"
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)
                
                elif SearchKeyword == "Case Severity Codes":
                    del RAW_JSONdata['disabled'] #required to delete b/c this cannot be set via API
                    endpoint_path = "/rest/severity"
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)
                
                elif SearchKeyword == "CEFs":
                    endpoint_path = "/rest/cef"  
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)   
                
                elif SearchKeyword == "container_statuses":
                    del RAW_JSONdata['disabled'] #required to delete b/c this cannot be set via API
                    endpoint_path = "/rest/container_status"
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)
                
                elif SearchKeyword == "Labels":                                                   
                    endpoint_path = "/rest/system_settings/events"
                    for _label in RAW_JSONdata['label']:
                        #output_json = {"add_label": "true", "label_name": _label}  
                        output_json = {"add_tag": "true", "tag_name": _label}                               
                        response = self.post_data(action_result, endpoint_path, output_json) 
                        if response:      
                            print(response)                        
                            if response.get('success'): #if 'Success' is found it returnes the Keys value
                                    print(f"You Successfully imported label: '{_label}'.")
                            else:
                                print(f"NOT Successfull importing label: '{_label}'. Error: {response['message']}") 
                        response = None #Reset
                
                elif SearchKeyword == "Tags": #we will have to create a container --> add the tags --> delete the container 
                    endpoint_path = "/rest/container"
                    output_json = {"name": "Temp Case Used to Create Tags", "label": "events", "tags": RAW_JSONdata['tags']}                               
                    response = self.post_data(action_result, endpoint_path, output_json)
                    List = []
                    List.append(response['id'])
                    Delete_json = {"ids": List}                        
                    #response = Delete_data(action_result, endpoint_path, Delete_json)   
                    #response = response[0] ## It returned a list so convert it back to a string                
                
                elif SearchKeyword == "HUDs": ## Hud 
                    endpoint_path = "/rest/container_pin_settings"    
                    response = self.post_data(endpoint_path, RAW_JSONdata)  
                
                elif SearchKeyword == "system_settings": 
                    endpoint_path = "/rest/system_settings"    
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)
                
                elif SearchKeyword == "playbook":                          
                    with open(f'{_file}', 'rb') as raw_b_file:                             
                        RAW_data = raw_b_file.read()
                        encoded_text = base64.b64encode(RAW_data).decode('utf-8')
                        output_json = {"playbook": encoded_text, "scm": "local", "force": True} ##Future Implementation to ask the user to force or not                       
                        endpoint_path = "/rest/import_playbook"    
                        response = self.post_data(action_result, endpoint_path, output_json)
                
                elif SearchKeyword == "custom_function":  
                    with open(f'{_file}', 'rb') as raw_b_file:                             
                        RAW_data = raw_b_file.read()
                        encoded_text = base64.b64encode(RAW_data).decode('utf-8')
                        output_json = {"custom_function": encoded_text, "scm": "local", "force": True} ##Future Implementation to ask the user to force or not                       
                        endpoint_path = "/rest/import_custom_function"    
                        response = self.post_data(action_result, endpoint_path, output_json)
                
                elif SearchKeyword == "container_options": 
                    endpoint_path = "/rest/system_settings"    
                    response = self.post_data(action_result, endpoint_path, RAW_JSONdata)
                    
                else:
                    return action_result.set_status(phantom.APP_ERROR, "Something went wrong reading the file. Make sure it is a file that was previously created by this app from the Export action.")
                                        
                                    
                if response:
                    action_result.add_data({"response_from_post_data": response})
                    if response.get('success'): #if 'Success' is found it returnes the Keys value
                        return action_result.set_status(phantom.APP_SUCCESS, "You Successfully imported your file")
                        
                    else:
                        return action_result.set_status(phantom.APP_ERROR, "NOT Successfull importing")
                     
        else:
            return action_result.set_status(phantom.APP_ERROR, "No Files detected in the File vault.")
        

        success_response_msg = "Success... But where????"
        return action_result.set_status(phantom.APP_SUCCESS, success_response_msg)

    def post_data(self, action_result, endpoint_path, RAW_JSONdata):
        
        All_responses = []
        for raw_item in RAW_JSONdata["data"]:
            action_result.add_data({"raw_Item_to_import": raw_item})
            
            formated_response_dict = {
                "json": raw_item
                }
            
            self.save_progress("Making Rest Call")
            # make rest call
            ret_val, response = self._make_rest_call(
                endpoint_path, action_result, params=None, method="post", **formated_response_dict
            )
            
            if phantom.is_fail(ret_val):
                self.save_progress("Failed make Rest Call")
                action_result.update_summary({"response": response, "ret_val": ret_val})
                return action_result.get_status()
            
            All_responses.append(response)
        
        return All_responses   
        
    def _handle_export_workbooks(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        success_response_msg = ""

        #Grab all the Available workbook template names and IDs first
        endpoint_path = "/rest/workbook_template?page_size=0" # page zero indicates all pages Refrence: https://docs.splunk.com/Documentation/SOARonprem/6.1.1/PlatformAPI/RESTQueryData

        self.save_progress("Making Rest Call")
        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint_path, action_result, params=None, method="get"
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
        
        endpoint_path = f"/rest/workbook_phase_template?_filter_template={WB_Template_ID}"
        
        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint_path, action_result, params=None, method="get"
        )
            
        
        if phantom.is_fail(ret_val):
            self.save_progress("Failed make Rest Call to get a Workbook IDs detailed data.")
            return action_result.get_status()
        
        if response:
            if response['count'] == 0:
                print(f"Something went wrong. Try confirming that the workbook ID exists") 

            else:           

                if WB_Data:                
                    _Name = WB_Data['name']
                    WB_Template_isdefault = WB_Data['is_default']
                    _Description = WB_Data['description']
                    _isnoterequired = WB_Data['is_note_required']

                    #FileName = f"workbook_template_export - {_Name}"                
                else: #When the function is called and only the ID is known
                    #if no name exists then go grab one
                    endpoint_path = f"workbook_template?_filter_id={WB_Template_ID}"                 
                    #api_url = "/rest/{endpoint_path}" # Construct the url for what we are looking for
                    #get_workbookinfo = (get_data(api_url)).json() # Making the GET request
                    #print(f"Raw Data: {get_workbookinfo['data']}")
                    #print(f"Raw Data: {response['data']}")
                    #_Name = get_workbookinfo['data'][0]['name']
                    #WB_Template_isdefault = get_workbookinfo['data'][0]['is_default']
                    #_Description = get_workbookinfo['data'][0]['description']
                    #_isnoterequired = get_workbookinfo['data'][0]['is_note_required']
                    #FileName = f"workbook_template_export - {_Name}"

                success_response_msg = f"{response['count']} Phases where exported from WorkBook ID: {WB_Template_ID} -- Name: {_Name}"
                
                action_result.update_summary({f"Success_RequestSingleWorkbook_{WB_Data['id']}": success_response_msg})
                
                # Add 'name' and is_default to the begining of the json to store
                formated_response = {'name': _Name, 
                    'is_default': WB_Template_isdefault, 
                    'description': _Description, 
                    'is_note_required': _isnoterequired,
                    'file_location': Vault.get_vault_tmp_dir(),
                    **response}

                data_item = {
                    "workbook_data": formated_response                                    
                }
                
                action_result.add_data(data_item) 
                
        # Return success
        self.save_progress(success_response_msg)
        return formated_response
    
    def Export_Playbooks_and_CustomFunctions(self, param, endpoint_path, DataType):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        success_response_msg = ""

        self.save_progress("Making Rest Call")
        # make rest call
        ret_val, get_response = self._make_rest_call(
            endpoint_path, action_result, params=None, method="get"
        )
        
        ret_rest_value = {
                    "ret_val": ret_val,
                    "get_response": get_response, 
                    "Current Status": action_result.get_status(),
                    "Currant Msg": action_result.get_message(),    
                    "is_valid_json_With_Values": is_valid_json_With_Values(get_response)              
                }
        
        # get the asset config
        data_item = {
                    "Rest Call Retured Value": ret_rest_value                                    
                }
        
        action_result.add_data(data_item)        
            
        if phantom.is_fail(ret_val):
            self.save_progress("Failed make Rest Call to get all the Workbook IDs.")
            return action_result.get_status()
        
        
        is_file_created = False
        
        # Get the current date
        current_date = datetime.now()

        # Format the date in a file-name-friendly format (e.g., YYYY-MM-DD)
        date_str_for_filename = current_date.strftime("%Y-%m-%d")
        
        number_of_Items = 0

        all_data_combined = []
        
        if get_response:
            ResultCount = get_response.get("count", "") #Get the Key named 'count' or return "" if one doesnt exist. This ensures nothing breaks
            if ResultCount == 0:
                action_result.update_summary({"Error": "no data found to export.", "ErrorDataType": DataType, "Error_return_string": get_response})
                ErrorMsg = f"No {DataType} data was found"
                return action_result.set_status(phantom.APP_ERROR, ErrorMsg)
            else:
                dataItems = [item for item in get_response['data']]
                print(f" ~~~~{DataType}s found~~~~ ")

                action_result.add_data({"dataItems_found": dataItems})

                number_of_Items = len(dataItems)

                for Eachitem_Json in dataItems:
                    id = Eachitem_Json['id']
                    formated_response = self.RequestSinglePlaybook_or_CustomFunction(action_result, id, DataType, Eachitem_Json)

                    all_data_combined.append(formated_response)
                
                FileName = f"{DataType}_export - {str(number_of_Items)} {DataType} exported - {date_str_for_filename}" 
                   
                is_file_created = self.create_file(param, all_data_combined, FileName, ".tgz", DataType)  

                if is_file_created:
                    action_result.update_summary({"Files_Successfully_Created": {"File_Name": FileName}})
                    success_response_msg = "Found & exported " + str(number_of_Items) + " " + DataType + ". Check Files in this container."
                    return action_result.set_status(phantom.APP_SUCCESS, success_response_msg)
                else:
                    action_result.update_summary({"Files_Failed_To_Create": {"File_Name": FileName}})
                    return action_result.set_status(phantom.APP_ERROR, "Something went wrong creating the file")

    def RequestSinglePlaybook_or_CustomFunction(self, action_result, id, DataType, Eachitem_Json):
        
        #action_result.update_summary({id: {"DataType": DataType, "data": Eachitem_Json}})
        
        endpoint_path = f"/rest/{DataType}/{id}/export"
        
        
        # make rest call
        ret_val, response = self._make_rest_call(
            endpoint_path, action_result, params=None, method="get"
        )
       
        
        #action_result.update_summary({id: {"DataType": DataType, "data": Eachitem_Json, "response": response}})    
        
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to make Rest Call to get detailed data.")
            return action_result.get_status()
        
                      
        _Name = Eachitem_Json['name']   
                           
        success_response_msg = f"{DataType} where exported from {DataType} ID: {id} -- Name: {_Name}"
        
        action_result.update_summary({f"Success_RequestSinglePlaybook_or_customFunction_{Eachitem_Json['id']}": success_response_msg})

        data_item = {
            "response_data": response                                    
        }
        
        action_result.add_data(data_item) 
                
        # Return success
        self.save_progress(success_response_msg)
        return response
    
    def RequestAllSpecificData(self, param, endpoint_path, DataType, KeyWordForName):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        
        success_response_msg = ""

        self.save_progress("Making Rest Call")
        # make rest call
        ret_val, get_response = self._make_rest_call(
            endpoint_path, action_result, params=None, method="get"
        )
        
        ret_rest_value = {
                    "ret_val": ret_val,
                    "get_response": get_response, 
                    "Current Status": action_result.get_status(),
                    "Currant Msg": action_result.get_message(),    
                    "is_valid_json_With_Values": is_valid_json_With_Values(get_response)              
                }
        
        # get the asset config
        data_item = {
                    "Rest Call Retured Value": ret_rest_value                                    
                }
        
        action_result.add_data(data_item)        
            
        if phantom.is_fail(ret_val):
            self.save_progress("Failed make Rest Call to get all the Workbook IDs.")
            return action_result.get_status()
        
        
        is_file_created = False
        
        # Get the current date
        current_date = datetime.now()

        # Format the date in a file-name-friendly format (e.g., YYYY-MM-DD)
        date_str_for_filename = current_date.strftime("%Y-%m-%d")
        
        number_of_Items = 0
        
        if get_response:
            isResponseHaveValues = is_valid_json_With_Values(get_response)
            ResultCount = get_response.get("count", "") #Get the Key named 'count' or return "" if one doesnt exist. This ensures nothing breaks
            if isResponseHaveValues and ResultCount == 0:
                action_result.update_summary({"Error": "no data found to export.", "ErrorDataType": DataType, "Error_return_string": get_response})
                ErrorMsg = f"No {DataType} data was found"
                return action_result.set_status(phantom.APP_ERROR, ErrorMsg)
            elif isResponseHaveValues and ResultCount == "": #In the case that there is no count in the JSON string so we save it all as one file
                
                if get_response.get(KeyWordForName, ""): #Only get the data you need if it is available.
                    get_response = {KeyWordForName: get_response[KeyWordForName]} #This helps us retain the key with the values instead of just the values
                action_result.add_data({"dataItems_found": get_response})
                number_of_Items = len(get_response)
                FileName = f"{DataType}_export - {number_of_Items} {DataType} exported - {date_str_for_filename}"
                
                is_file_created = self.create_file(param, get_response, FileName, ".json", DataType)        
            elif isResponseHaveValues and ResultCount != 0:

                dataItems = [item for item in get_response['data']]                
                #print(f" ~~~~{DataType}s found~~~~ ")

                action_result.add_data({"dataItems_found": dataItems})

                number_of_Items = len(dataItems)
                
                FileName = f"{DataType}_export - {number_of_Items} {DataType} exported - {date_str_for_filename}" 
                   
                is_file_created = self.create_file(param, dataItems, FileName, ".json", DataType)
                
            else:
                action_result.update_summary({"Error": "Looks like Valid a VALID JSON string was not returned", "ErrorDataType": DataType, "Error_return_string": get_response})
                return action_result.set_status(phantom.APP_ERROR, "Something went wrong getting all the available data for - " + DataType + ".")
                #print(f"Something went wrong getting all the available data for - {DataType}.") 
                #print(f"Looks like Valid a VALID JSON string was not returned") 
                #print(f"Error String: {get_response}")   
        
        
        if is_file_created:
            action_result.update_summary({"Files_Successfully_Created": {"File_Name": FileName}})
            success_response_msg = "Found & exported " + str(number_of_Items) + " " + DataType + ". Check Files in this container."
            return action_result.set_status(phantom.APP_SUCCESS, success_response_msg)
        else:
            action_result.update_summary({"Files_Failed_To_Create": {"File_Name": FileName}})
            return action_result.set_status(phantom.APP_ERROR, "Something went wrong creating the file to export - " + DataType + ".")
            


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

    def get_json_from_file(self, action_result, filePath):

        RAW_JSONdata = ""
        with open(f'{filePath}', 'r') as raw_file:
            #Parse the JSON data into a Python dictionary
            RAW_JSONdata = json.load(raw_file)
            

        return RAW_JSONdata
    
    def get_all_files_in_vault(self, action_result):

        container_id = self.get_container_id()
        vault_info_success, vault_info_message, vault_info_data = vault.vault_info(vault_id=None, file_name=None, container_id=container_id, trace=True)
        action_result.add_data({"vault_info_success": vault_info_success, "vault_info_message": vault_info_message, "vault_info_data": vault_info_data})
        #action_result.add_data({"path": vault_info_data[0]["path"]})
        return vault_info_data
 
    
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
            '/rest/system_info', action_result, params=None, method="get"
        )
        data_item = {
                    "Response": response,
                    "ret_val": ret_val
                }
        
        action_result.add_data(data_item)

        
        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
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
            ret_val = self.handle_export_flow(param)
            
        if action_id == 'import':
            ret_val = self._handle_import(param)
        

        return ret_val

    def handle_export_flow(self, param):
    
        if param["Items to Export"] in ('Workbooks', 'ALL'):  
            ret_val = self._handle_export_workbooks(param)
            
        if param["Items to Export"] in ('Users', 'ALL'):
            endpoint_path = "/rest/ph_user?page_size=0" # page zero indicates all pages Refrence: https://docs.splunk.com/Documentation/SOARonprem/6.1.1/PlatformAPI/RESTQueryData
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "Users", "username")
            
        if param["Items to Export"] in ('Roles', 'ALL'):
            endpoint_path = "/rest/role?page_size=0" # page zero indicates all pages Refrence: https://docs.splunk.com/Documentation/SOARonprem/6.1.1/PlatformAPI/RESTQueryData
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "Roles", "name")

        if param["Items to Export"] in ('Case Severity Codes', 'ALL'):
            print("Exporting Severitys...")
            endpoint_path = "/rest/severity?page_size=0"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "Case Severity Codes", "name") #command, DataType, Keyword for name
        
        if param["Items to Export"] in ('CEFs', 'ALL'):
            print("Exporting CEFs...") 
            endpoint_path = "/rest/cef?_filter_type=\"custom\"&page_size=0"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "CEFs", "name") #command, DataType, Keyword for name

        if param["Items to Export"] in ('Case Statuses', 'ALL'):
            print("Exporting Case Statuses...")
            endpoint_path = "/rest/container_status?page_size=0" # page zero indicates all pages Refrence: https://docs.splunk.com/Documentation/SOARonprem/6.1.1/PlatformAPI/RESTQueryData
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "container_statuses", "name") #command, DataType, Keyword for name

        if param["Items to Export"] in ('Labels', 'ALL'):
            print("Exporting Labels...") 
            endpoint_path = "/rest/container_options/label"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "Labels", "label") #command, DataType, Keyword for name

        if param["Items to Export"] in ('Tags', 'ALL'):
            print("Exporting Tags...") 
            endpoint_path = "/rest/container_options/tags"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "Tags", "tags") #command, DataType, Keyword for name
    
        if param["Items to Export"] in ('HUDs', 'ALL'):    
            print("Exporting HUD...") 
            endpoint_path = "/rest/container_pin_settings?page_size=0"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "HUDs", "id") #command, DataType, Keyword for name

        if param["Items to Export"] in ('Playbooks', 'ALL'):
            print("Exporting Playbooks...")        
            endpoint_path = "/rest/playbook?page_size=0"
            ret_val = self.Export_Playbooks_and_CustomFunctions(param, endpoint_path, "playbook") #command, DataType

        if param["Items to Export"] in ('Custom Functions', 'ALL'):
            print("Exporting Custom Functions...")
            endpoint_path = "/rest/custom_function?page_size=0"
            ret_val = self.Export_Playbooks_and_CustomFunctions(param, endpoint_path, "custom_function")

        if param["Items to Export"] in ('System Settings', 'ALL'):
            print("Exporting all other settings ...") 
            endpoint_path = "/rest/system_settings"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "system_settings", "name") #command, DataType, Keyword for name
            
        if param["Items to Export"] in ('Container Options', 'ALL'):
            print("Exporting Container Options...") 
            endpoint_path = "/rest/container_options"
            ret_val = self.RequestAllSpecificData(param, endpoint_path, "container_options", "") #command, DataType, Keyword for name
                
    
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
