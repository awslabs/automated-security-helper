from jinja2 import Template
import sys
files = sys.argv[1:]
#print (files)
with open('/utils/cfn-to-cdk/cfn_to_cdk/cfn_to_cdk_stack.py.j2') as f:
    template = Template(f.read())

b=template.render(enumerate=enumerate, files=files)
with open("/utils/cfn-to-cdk/cfn_to_cdk/cfn_to_cdk_stack.py", "w") as fh:
    fh.write(b)
