def convert_workbook_into_importable_JSON(input_json):

    # Parse the input JSON
    data = input_json

    Template_name = data["name"]
    Template_isdefault = data["is_default"]
    Template_description = data["description"] 
    Template_isnoterequired = data["is_note_required"]

    # Initialize the output structure
    output_data = {
        "name": Template_name,
        "description": Template_description,
        "is_default": Template_isdefault,
        "is_note_required": Template_isnoterequired,
        "phases": []
    }

    # Loop through the phases in the input JSON and transform them
    for phase in data["data"]:
        phase_name = phase["name"]
        phase_order = phase["order"]
        phase_tasks = phase["tasks"]
        phase_sla = phase["sla"]
        phase_sla_type = phase["sla_type"]


        # Initialize the phase structure for the output
        phase_data = {
            "name": phase_name,
            "order": phase_order,
            "sla": phase_sla,
            "sla_type": phase_sla_type,
            "tasks": []
        }

        # Loop through the tasks in the phase and transform them
        for task in phase_tasks:
            task_name = task["name"]
            task_order = task["order"]
            task_description = task["description"]
            task_owner = task["owner"]
            task_role = task["role"]
            task_is_note_required = task["is_note_required"]
            task_sla = task["sla"]
            task_sla_type = task["sla_type"]
            task_suggestions = task["suggestions"]
            task_actions = task_suggestions.get("actions", [])
            task_playbooks = task_suggestions.get("playbooks", [])


            # Initialize the task structure for the output
            task_data = {
                "name": task_name,
                "order": task_order,
                "description": task_description,
                "owner": task_owner,
                "role": task_role,
                "is_note_required": task_is_note_required,
                "sla": task_sla,
                "sla_type": task_sla_type                
            }

            #only add it if there are actions
            if task_actions:
                task_data["actions"] = task_actions

            #only add it if there are playbooks
            if task_playbooks:
                playbooksList = []
                # Loop through the task playbooks
                for playbook in task_playbooks:
                    playbook_scm = playbook["scm"]
                    playbook_name = playbook["playbook"]

                    # Initialize the playbook structure for the output
                    playbook_data = {
                        "scm": playbook_scm,
                        "playbook": playbook_name
                    }

                    # Add the task to the phase
                    playbooksList.append(playbook_data)
                    task_data["playbooks"] = playbooksList

            # Add the task to the phase
            phase_data["tasks"].append(task_data)

        # Add the phase to the output
        output_data["phases"].append(phase_data)

    # Convert the output data to JSON format
    output_json = output_data #json.loads(output_data)
    #print("File successfully converted to readable input file!")
    #print(output_json)
    return output_json

def RequestAllSpecificData(Cmd, DataType, KeyWordForName):
    # Construct the url for what we are looking for
    api_url = f"https://{username}:{password}@{host}/rest/{Cmd}"

    # Making the GET request
    get_response = (get_data(api_url)).json()

    #print(f"Raw Data - for {DataType}: {get_response}") 

    if get_response:
        isResponseHaveValues = is_valid_json_With_Values(get_response)
        ResultCount = get_response.get("count", "") #Get the Key named 'count' or return "" if one doesnt exist. This ensures nothing breaks
        if isResponseHaveValues and ResultCount == 0:
            print(f"No {DataType} data found to import.") 
            print(f"Return string: {get_response}")
            input("Continue.....")
        elif isResponseHaveValues and ResultCount == "": #In the case that thier is no count in the JSON string so we save it all as one file
            print(f" ~~~~{DataType}s found~~~~ ")
            FileName = f"{DataType}_export - All in one"
            if get_response.get(KeyWordForName, ""): #Only get the data you need if it is available.
                get_response = {KeyWordForName: get_response[KeyWordForName]} #This helps us retain the key with the values instead of just the values
            create_file(get_response, FileName, ".json") #Last perameter is file type               
            input("Continue.....")   
        elif isResponseHaveValues and ResultCount != 0:

            dataItems = [item for item in get_response['data']]
            print(f" ~~~~{DataType}s found~~~~ ")

            for Eachitem in dataItems:
                print(f"{DataType}: {Eachitem[KeyWordForName]}")
                JsonToStore = Eachitem
                FileName = f"{DataType}_export - {Eachitem[KeyWordForName]}"
                create_file(JsonToStore, FileName, ".json") #Last perameter is file type               

                print("-----------------------------------------------")

            input("Continue.....")     
        else:
            print(f"Something went wrong getting all the available data for - {DataType}.") 
            print(f"Looks like Valid a VALID JSON string was not returned") 
            print(f"Error String: {get_response}")   
            input("Continue.....")       

def Export_Playbooks_and_CustomFunctions(Cmd, DataType):
    # Construct the url 
    api_url = f"https://{username}:{password}@{host}/rest/{Cmd}"

    # Making the GET request to get all IDs first
    get_response = (get_data(api_url)).json()

    #print(f"Raw Data - for {DataType}: {get_response}") 

    if get_response:
        ResultCount = get_response.get("count", "") #Get the Key named 'count' or return "" if one doesnt exist. This ensures nothing breaks
        if ResultCount == 0:
            print(f"Something went wrong getting all the available data for - {DataType}.") 
            print(f"Error String: {get_response}")
            input("Continue.....")
        else:
            dataItems = [item for item in get_response['data']]
            print(f" ~~~~{DataType}s found~~~~ ")

            for Eachitem_Json in dataItems:
                id = Eachitem_Json['id']
                print(f"{DataType}: {Eachitem_Json['name']} - ID:{id}")
                #print(f"Raw: {Eachitem_Json}")                
                FileNameTGZ = f"{DataType}_export - {Eachitem_Json['name']}"
                FileNameRawText = f"{DataType}_export - {Eachitem_Json['name']}"
                Cmd = f"{DataType}/{id}/export"
                #Cmd = f"custom_function/1/export"
                # Construct the url 
                api_url = f"https://{username}:{password}@{host}/rest/{Cmd}"

                # Making the GET request to get all IDs first
                get_response = get_data(api_url)
                #print(f"Raw TGZ: {get_response.content}")
                create_file(get_response, FileNameTGZ, ".tgz") #Last perameter is file type    
                #create_file(get_response, FileNameRawText, ".txt") #Last perameter is file type               

                print("-----------------------------------------------")

            input("Continue.....")   
            
def is_valid_json_With_Values(data):
    return isinstance(data, dict) and len(data) >= 1