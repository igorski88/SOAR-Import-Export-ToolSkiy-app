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