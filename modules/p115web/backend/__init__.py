import os
if not os.environ.get("WORKDIR"):
    workdir = os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))), 'data')
else:
    workdir = os.environ.get("WORKDIR")
if not os.path.exists(workdir):
    os.makedirs(workdir)
log_dir = os.path.join(workdir, 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
conf_dir = os.path.join(workdir, 'conf')
if not os.path.exists(conf_dir):
    os.makedirs(conf_dir)

if not os.path.exists(f'{workdir}/115-cookies.txt'):
    with open(f'{workdir}/115-cookies.txt', 'w', encoding='utf-8') as file:
        file.write('')
os.environ["WORKDIR"] = workdir