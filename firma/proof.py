import aspose.pdf as pdf
import aspose.pydrawing as drawing

# Set the source directory path
filePath = "D:/"

# Load the license in your application to crop the PDF
pdfCropLicense = pdf.License()
pdfCropLicense.set_license(filePath + "Conholdate.Total.Product.Family.lic")

#Load the PDF file to crop
pdfDoc = pdf.Document(filePath + "pruebaFirma.pdf")

#Instantiate the PdfFileSignature for the loaded PDF document
signature = pdf.facades.PdfFileSignature(pdfDoc)

#Load the certificate file along with the password
pkcs = pdf.forms.PKCS7(filePath + "1350552327.p12", "Josecm2024")

#Assign the access permissions
docMdpSignature = pdf.forms.DocMDPSignature(pkcs, pdf.forms.DocMDPAccessPermissions.FILLING_IN_FORMS)

#Set the rectangle for the signature placement
rect = drawing.Rectangle(150, 650, 450, 150)

#Set signature appearance
signature.signature_appearance = "sample.jpg"

#Sign the PDF file with the certify method
signature.certify(1, "Signature Insert  Reason", "Contact", "Location", True, rect, docMdpSignature)

#Save digitally signed PDF file 
signature.save("Digitally Signed PDF.pdf")

print("Done")