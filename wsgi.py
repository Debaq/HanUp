import sys
import os

# Añadir el directorio de la aplicación al path de Python
sys.path.insert(0, '/home/tmeducao/public_html/handup')

# Activar el entorno virtual
activate_this = '/home/tmeducao/virtualenv/public_html/handup/3.12/bin/activate_this.py'
exec(open(activate_this).read(), {'__file__': activate_this})

from app import app as application