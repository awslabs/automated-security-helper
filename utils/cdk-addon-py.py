
def add_cdk_nag_imports(filename):
    cdk_nag_imports = ["\nfrom cdk_nag import AwsSolutionsChecks","\nfrom aws_cdk import App, Aspects"]
    for cdk_import in cdk_nag_imports:
        with open(filename, 'r') as cdk_app_file:
            cdk_app_file_data = cdk_app_file.read()
        if cdk_import in cdk_app_file_data:
#            print(cdk_import + ' already exists')
            pass
        else:
            missing_import = '#!/usr/bin/env python3' + cdk_import
            cdk_app_file_data = cdk_app_file_data.replace('#!/usr/bin/env python3', missing_import )
            with open(filename, 'w') as cdk_app_file:
#                print('Adding '+ missing_import)
                cdk_app_file.write(cdk_app_file_data)

def add_cdk_nag_checks(filename):
    cdk_nag_check = "\nAspects.of(app).add(AwsSolutionsChecks())\n"
    with open(filename, 'r') as cdk_app_file:
        cdk_app_file_data = cdk_app_file.read()
    if cdk_nag_check in cdk_app_file_data:
#        print(cdk_nag_check + ' already exists')
        pass
    else:
        missing_check = cdk_nag_check + 'app.synth()'
        cdk_app_file_data = cdk_app_file_data.replace('app.synth()', missing_check )
        with open(filename, 'w') as cdk_app_file:
#            print('Adding '+ missing_check)
            cdk_app_file.write(cdk_app_file_data)


 
filename = "app.py"
add_cdk_nag_imports(filename)
add_cdk_nag_checks(filename)
