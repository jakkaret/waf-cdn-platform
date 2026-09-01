import subprocess
try:
    res = subprocess.run(["docker", "exec", "waf-nginx", "nginx", "-t"], capture_output=True)
    print("STDOUT:", res.stdout.decode('utf-8'))
    print("STDERR:", res.stderr.decode('utf-8'))
except Exception as e:
    print(e)
