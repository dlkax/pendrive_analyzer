import os
from watchdog.observers import FileSystemEventHandler
from watchdog.observers import Observer 
import hashlib
import time
import string  # Para listar drives (A: até Z:

#class para monitoramento do pendrive:
class PendriveHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            print(f"Novo arquivo detectado: {event.src_path}")
            analise_file(event.src_path)

#função pra calcular o hash md5 de um arquivo:
def calcular_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

#função pra analisar o arquivo
def analise_file(file_path):
    #adicionando extensões suspeitas
    suspicious_extensions = [".bat", ".exe", ".vbs", ".scr", ".js"]
    file_extension = os.path.splitext(file_path)[1].lower()

    #verificar extensão
    if file_extension in suspicious_extensions:
        print(f"⚠️ Arquivo suspeito encontrado: {file_path} (extensão: {file_extension})")

    #calcular o hash
    file_hash = calcular_hash(file_path)
    print(f"hash MD5: {file_path}")

    #hashes conhecidos (adicione mais em uma lista ou banco)
    known_malware_hashes = ["e99a18c428cb38d5f260853678922e03"] #exemplo de hash
    if file_hash in known_malware_hashes:
        print(f"🚨 Malware detectado: {file_path}")
    else:
        print(f"✅ Arquivo parece seguro.")
    
#função para monitoramento de drivers:
def monitorar_drivers():

    observer = Observer()
    monitored_paths = []

    while True:
        #lista todas as letras de drivers possiveis 
        drivers = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]

        for drive in drivers:
            if drive not in monitored_paths and os.path.isdir(drive):
                print(f"Pendrive detectado: {drive}")
                event_handler = PendriveHandler()
                observer.schedule(event_handler, drive, recursive=True)
                observer.start()
                monitored_paths.append(drive)

        time.sleep(1) #verificar a cada 1 segundo

if __name__ == "__main__":
    print("Iniciando monitoramento de pendrives...")
    monitorar_drivers()