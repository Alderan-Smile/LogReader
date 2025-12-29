# Log Viewer (Python)

Visor simple de logs remotos (por URL) en Python usando `tkinter`.

Características:
- Abrir múltiples pestañas (cada pestaña una URL de log).
- Lectura continua: el programa solicita solo bytes nuevos cuando el servidor soporta `Range`.
- Controles por pestaña: pausar/reanudar, ajustar intervalo, limpiar, auto-scroll.

Requisitos
- Python 3.8+
- `requests` (ver `requirements.txt`)

Instalación

```bash
python -m pip install -r requirements.txt
```

Uso

```bash
python main.py
```

En la aplicación, use "Archivo → Añadir log..." para añadir una URL como `http://web.com/LOGS/estoEsUnLog.log`.

Notas
- El lector intenta usar la cabecera HTTP `Range` para pedir solo los bytes nuevos. Si el servidor no lo soporta, el cliente pedirá el archivo completo y mostrará solo la porción nueva.
- Ajuste el intervalo de refresco por pestaña según la frecuencia de actualización del log.
