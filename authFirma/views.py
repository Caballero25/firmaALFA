import io
from django.shortcuts import render
# *-* coding: utf-8 *-*
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive.pdf import cms
import io 
import base64
from django.shortcuts import render
from django.http import JsonResponse
from .forms import DocumentForm
import datetime

##############           PRUEBA 01 ################################## BUENA ########################################################################
def prueba01(request):
    if request.method == 'POST':
        form = DocumentForm(request.POST, request.FILES)
        pagina = request.POST.get('pagina')
        coordenadaX = float(request.POST.get('coordenadaX'))
        coordenadaY = float(request.POST.get('coordenadaY'))
        coordenadaX = coordenadaX 
        coordenadaY = coordenadaY
        print(coordenadaX)
        print(coordenadaY)
        print("pagina " + pagina)
        if form.is_valid():
            pdf_file = request.FILES['pdf']
            p12_file = request.FILES['p12']
            password = form.cleaned_data['password']
            
            # Leer el contenido del archivo PDF subido
            pdf_bytes = pdf_file.read()
            pdf_stream = io.BytesIO(pdf_bytes)
            
            # Leer el contenido del archivo P12 subido
            p12_bytes = p12_file.read()
            p12_stream = io.BytesIO(p12_bytes)

            date = datetime.datetime.now()

            date = date.strftime("D:%Y%m%d%H%M%S")
            #Cargar y validar certificado
            p12 = pkcs12.load_key_and_certificates(
                p12_stream.read(), password.encode("ascii"), backends.default_backend()
            )
            
            #Acceder a toda la información del certificado:
            private_key = p12[0]
            if private_key:
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )


            # Extraer el certificado
            certificateDataUser = p12[1]
                
            # Obtener el sujeto del certificado
            subject = certificateDataUser.subject
            dataSignatory = {}
            for attribute in subject:
                print(str(attribute.oid._name) + " exitoso")
                dataSignatory[attribute.oid._name] = attribute.value

            
            signature_text = f"Firma digital de\n{dataSignatory['commonName']}"
            dct = {
                "aligned": 0,
                "sigflags": 3,
                "sigflagsft": 132,
                "sigpage": int(pagina)-1,
                "sigbutton": True,
                "sigfield": "Signature",
                "auto_sigfield": True,
                "sigandcertify": True,
                "signaturebox": (float(coordenadaX), float(coordenadaY-75), float(coordenadaX)+128, float(coordenadaY)-120),
                "signature": signature_text,
                #"signature_img": signature_image_path,
                "contact": dataSignatory['emailAddress'],
                "location": "Ubicación",
                "signingdate": date,
                "reason": "Razón",
                "password": password,
            }

            datau = pdf_stream.read()
            datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
            archivo_pdf_para_enviar_al_cliente = io.BytesIO()
            archivo_pdf_para_enviar_al_cliente.write(datau)
            archivo_pdf_para_enviar_al_cliente.write(datas)
            archivo_pdf_para_enviar_al_cliente.seek(0)
            # Codificar el flujo de bytes en base64
            signed_pdf_base64 = base64.b64encode(archivo_pdf_para_enviar_al_cliente.read()).decode('utf-8')
            
            
            
            # Eliminar la imagen temporal
            #os.remove(signature_image_path)
        

            return JsonResponse({'message': 'Archivo subido con éxito!', 'signed_pdf': signed_pdf_base64})
        else:
            return JsonResponse({'message': 'Error al subir el archivo'}, status=400)
    else:
        form = DocumentForm()
    return render(request, 'prueba03.html', {'form': form})

