.\venv\Scripts\Activate.ps1
pyinstaller --onefile --windowed --icon=app.ico --distpath "C:\SAP\Digi_Sign" --add-data "tick.png;." --add-data "trebuc.ttf;." DigiSign.py