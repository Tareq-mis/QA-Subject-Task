
import site, sys

site.addsitedir('../../../PDFNetC/Lib')

from PDFNetPython import *

def VerifyAllAndPrint(in_docpath, in_public_key_file_path):
	doc = PDFDoc(in_docpath)
	print("==========")
	opts = VerificationOptions(VerificationOptions.e_compatibility_and_archiving)
	
	# Trust the public certificate we use for signing.
	trusted_cert_buf = []
	trusted_cert_file = MappedFile(in_public_key_file_path)
	file_sz = trusted_cert_file.FileSize()
	file_reader = FilterReader(trusted_cert_file)
	trusted_cert_buf = file_reader.Read(file_sz)
	opts.AddTrustedCertificate(trusted_cert_buf)

	# Iterate over the signatures and verify all of them.
	digsig_fitr = doc.GetDigitalSignatureFieldIterator()
	verification_status = True
	while (digsig_fitr.HasNext()):
		curr = digsig_fitr.Current()
		result = curr.Verify(opts)
		if result.GetVerificationStatus():
			print("Signature verified, objnum: %lu" % curr.GetSDFObj().GetObjNum())
		else:
			print("Signature verification failed, objnum: %lu" % curr.GetSDFObj().GetObjNum())
			verification_status = False

		digest_algorithm = result.GetSignersDigestAlgorithm()
		if digest_algorithm is DigestAlgorithm.e_SHA1:
			print("Digest algorithm: SHA-1")
		elif digest_algorithm is DigestAlgorithm.e_SHA256:
			print("Digest algorithm: SHA-256")
		elif digest_algorithm is DigestAlgorithm.e_SHA384:
			print("Digest algorithm: SHA-384")
		elif digest_algorithm is DigestAlgorithm.e_SHA512:
			print("Digest algorithm: SHA-512")
		elif digest_algorithm is DigestAlgorithm.e_RIPEMD160:
			print("Digest algorithm: RIPEMD-160")
		elif digest_algorithm is DigestAlgorithm.e_unknown_digest_algorithm:
			print("Digest algorithm: unknown")
		else:
			assert False, "unrecognized document status"

		print("Detailed verification result: ")
		doc_status = result.GetDocumentStatus()
		if doc_status is VerificationResult.e_no_error:
			print("\tNo general error to report.")
		elif doc_status is VerificationResult.e_corrupt_file:
			print("\tSignatureHandler reported file corruption.")
		elif doc_status is VerificationResult.e_unsigned:
			print("\tThe signature has not yet been cryptographically signed.")
		elif doc_status is VerificationResult.e_bad_byteranges:
			print("\tSignatureHandler reports corruption in the ByteRanges in the digital signature.")
		elif doc_status is VerificationResult.e_corrupt_cryptographic_contents:
			print("\tSignatureHandler reports corruption in the Contents of the digital signature.")
		else:
			assert False, "unrecognized document status"
		
		digest_status = result.GetDigestStatus()
		if digest_status is VerificationResult.e_digest_invalid:
			print("\tThe digest is incorrect.")
		elif digest_status is VerificationResult.e_digest_verified:
			print("\tThe digest is correct.")
		elif digest_status is VerificationResult.e_digest_verification_disabled:
			print("\tDigest verification has been disabled.")
		elif digest_status is VerificationResult.e_weak_digest_algorithm_but_digest_verifiable:
			print("\tThe digest is correct, but the digest algorithm is weak and not secure.")
		elif digest_status is VerificationResult.e_no_digest_status:
			print( "\tNo digest status to report.")
		elif digest_status is VerificationResult.e_unsupported_encoding:
			print("\tNo installed SignatureHandler was able to recognize the signature's encoding.")
		else:
			assert False, "unrecognized digest status"
		
		trust_status = result.GetTrustStatus()
		if trust_status is VerificationResult.e_trust_verified:
			print("\tEstablished trust in signer successfully.")
		elif trust_status is VerificationResult.e_untrusted:
			print("\tTrust could not be established.")
		elif trust_status is VerificationResult.e_trust_verification_disabled:
			print("\tTrust verification has been disabled.")
		elif trust_status is VerificationResult.e_no_trust_status:
			print("\tNo trust status to report.")
		else:
			assert False, "unrecognized trust status"
		
		permissions_status = result.GetPermissionsStatus()
		if permissions_status is VerificationResult.e_invalidated_by_disallowed_changes:
			print("\tThe document has changes that are disallowed by the signature's permissions settings.")
		elif permissions_status is VerificationResult.e_has_allowed_changes:
			print("\tThe document has changes that are allowed by the signature's permissions settings.")
		elif permissions_status is VerificationResult.e_unmodified:
			print("\tThe document has not been modified since it was signed.")
		elif permissions_status is VerificationResult.e_permissions_verification_disabled:
			print("\tPermissions verification has been disabled.")
		elif permissions_status is VerificationResult.e_no_permissions_status:
			print("\tNo permissions status to report.")
		else:
			assert False, "unrecognized modification permissions status"
		
		changes = result.GetDisallowedChanges()
		for it2 in changes:
			print("\tDisallowed change: %s, objnum: %lu" % (it2.GetTypeAsString(), it2.GetObjNum()))
		
		# Get and print all the detailed trust-related results, if they are available.
		if result.HasTrustVerificationResult():
			trust_verification_result = result.GetTrustVerificationResult()
			print("Trust verified." if trust_verification_result.WasSuccessful() else "Trust not verifiable.")
			print("Trust verification result string: %s" % trust_verification_result.GetResultString())
			
			tmp_time_t = trust_verification_result.GetTimeOfTrustVerification()
			
			trust_verification_time_enum = trust_verification_result.GetTimeOfTrustVerificationEnum()
			
			if trust_verification_time_enum is VerificationOptions.e_current:
				print("Trust verification attempted with respect to current time (as epoch time): " + str(tmp_time_t))
			elif trust_verification_time_enum is VerificationOptions.e_signing:
				print("Trust verification attempted with respect to signing time (as epoch time): " + str(tmp_time_t))
			elif trust_verification_time_enum is VerificationOptions.e_timestamp:
				print("Trust verification attempted with respect to secure embedded timestamp (as epoch time): " + str(tmp_time_t))
			else:
				assert False, "unrecognized time enum value"
			
		else:
			print("No detailed trust verification result available.")
		
		print("==========")
		
		digsig_fitr.Next()

	return verification_status

def CertifyPDF(in_docpath,
	in_cert_field_name,
	in_private_key_file_path,
	in_keyfile_password,
	in_appearance_image_path,
	in_outpath):
	
	print('================================================================================')
	print('Certifying PDF document')

	# Open an existing PDF
	doc = PDFDoc(in_docpath)

	if doc.HasSignatures():
		print('PDFDoc has signatures')
	else:
		print('PDFDoc has no signatures')

	page1 = doc.GetPage(1)

	
	annot1 = TextWidget.Create(doc, Rect(50, 550, 350, 600), "asdf_test_field")
	page1.AnnotPushBack(annot1)

	certification_sig_field = doc.CreateDigitalSignatureField(in_cert_field_name)
	widgetAnnot = SignatureWidget.Create(doc, Rect(0, 100, 200, 150), certification_sig_field)
	page1.AnnotPushBack(widgetAnnot)

	
	img = Image.Create(doc.GetSDFDoc(), in_appearance_image_path)
	widgetAnnot.CreateSignatureAppearance(img)

	
	print('Adding document permissions.')
	certification_sig_field.SetDocumentPermissions(DigitalSignatureField.e_annotating_formfilling_signing_allowed)
	
	
	print('Adding field permissions.')
	certification_sig_field.SetFieldPermissions(DigitalSignatureField.e_include, ['asdf_test_field'])

	certification_sig_field.CertifyOnNextSave(in_private_key_file_path, in_keyfile_password)

	
	certification_sig_field.SetLocation('Vancouver, BC')
	certification_sig_field.SetReason('Document certification.')
	certification_sig_field.SetContactInfo('www.pdftron.com')

	
	doc.Save(in_outpath, 0)

	print('================================================================================')

def SignPDF(in_docpath,	
	in_approval_field_name,	
	in_private_key_file_path, 
	in_keyfile_password, 
	in_appearance_img_path, 
	in_outpath):
	
	print('================================================================================')
	print('Signing PDF document')

	
	doc = PDFDoc(in_docpath)

	found_approval_field = doc.GetField(in_approval_field_name)
	found_approval_signature_digsig_field = DigitalSignatureField(found_approval_field)
	
	img = Image.Create(doc.GetSDFDoc(), in_appearance_img_path)
	found_approval_signature_widget = SignatureWidget(found_approval_field.GetSDFObj())
	found_approval_signature_widget.CreateSignatureAppearance(img)

	found_approval_signature_digsig_field.SignOnNextSave(in_private_key_file_path, in_keyfile_password)

	doc.Save(in_outpath, SDFDoc.e_incremental)

	print('================================================================================')

def ClearSignature(in_docpath,
	in_digsig_field_name,
	in_outpath):

	print('================================================================================')
	print('Clearing certification signature')

	doc = PDFDoc(in_docpath)

	digsig = DigitalSignatureField(doc.GetField(in_digsig_field_name))
	
	print('Clearing signature: ' + in_digsig_field_name)
	digsig.ClearSignature()

	if not digsig.HasCryptographicSignature():
		print('Cryptographic signature cleared properly.')

	doc.Save(in_outpath, SDFDoc.e_incremental)

	print('================================================================================')

def PrintSignaturesInfo(in_docpath):
	print('================================================================================')
	print('Reading and printing digital signature information')

	doc = PDFDoc(in_docpath)
	if not doc.HasSignatures():
		print('Doc has no signatures.')
		print('================================================================================')
		return
	else:
		print('Doc has signatures.')

	fitr = doc.GetFieldIterator()
	while fitr.HasNext():
		current = fitr.Current()
		if (current.IsLockedByDigitalSignature()):
			print("==========\nField locked by a digital signature")
		else:
			print("==========\nField not locked by a digital signature")

		print('Field name: ' + current.GetName())
		print('==========')
		
		fitr.Next()

	print("====================\nNow iterating over digital signatures only.\n====================")

	digsig_fitr = doc.GetDigitalSignatureFieldIterator()
	while digsig_fitr.HasNext():
		current = digsig_fitr.Current()
		print('==========')
		print('Field name of digital signature: ' + Field(current.GetSDFObj()).GetName())

		digsigfield = current
		if not digsigfield.HasCryptographicSignature():
			print("Either digital signature field lacks a digital signature dictionary, " +
				"or digital signature dictionary lacks a cryptographic hash entry. " +
				"Digital signature field is not presently considered signed.\n" +
				"==========")
			digsig_fitr.Next()
			continue

		cert_count = digsigfield.GetCertCount()
		print('Cert count: ' + str(cert_count))
		for i in range(cert_count):
			cert = digsigfield.GetCert(i)
			print('Cert #' + i + ' size: ' + cert.length)

		subfilter = digsigfield.GetSubFilter()

		print('Subfilter type: ' + str(subfilter))

		if subfilter is not DigitalSignatureField.e_ETSI_RFC3161:
			print('Signature\'s signer: ' + digsigfield.GetSignatureName())

			signing_time = digsigfield.GetSigningTime()
			if signing_time.IsValid():
				print('Signing day: ' + signing_time.GetDay())

			print('Location: ' + digsigfield.GetLocation())
			print('Reason: ' + digsigfield.GetReason())
			print('Contact info: ' + digsigfield.GetContactInfo())
		else:
			print('SubFilter == e_ETSI_RFC3161 (DocTimeStamp; no signing info)')

		if digsigfield.HasVisibleAppearance():
			print('Visible')
		else:
			print('Not visible')

		digsig_doc_perms = digsigfield.GetDocumentPermissions()
		locked_fields = digsigfield.GetLockedFields()
		for it in locked_fields:
			print('This digital signature locks a field named: ' + it)

		if digsig_doc_perms is DigitalSignatureField.e_no_changes_allowed:
			print('No changes to the document can be made without invalidating this digital signature.')
		elif digsig_doc_perms is DigitalSignatureField.e_formfilling_signing_allowed:
			print('Page template instantiation, form filling, and signing digital signatures are allowed without invalidating this digital signature.')
		elif digsig_doc_perms is DigitalSignatureField.e_annotating_formfilling_signing_allowed:
			print('Annotating, page template instantiation, form filling, and signing digital signatures are allowed without invalidating this digital signature.')
		elif DigitalSignatureField.e_unrestricted:
			print('Document not restricted by this digital signature.')
		else:
			print('Unrecognized digital signature document permission level.')
			assert(False)
		print('==========')
		digsig_fitr.Next()

	print('================================================================================')

def main():
	PDFNet.Initialize()
	
	result = True
	input_path = '../../TestFiles/'
	output_path = '../../TestFiles/Output/'
	
	#################### TEST 0:
	# Create an approval signature field that we can sign after certifying.
	# (Must be done before calling CertifyOnNextSave/SignOnNextSave/WithCustomHandler.)
	# Open an existing PDF
	try:
		doc = PDFDoc(input_path + 'tiger.pdf')
		
		widgetAnnotApproval = SignatureWidget.Create(doc, Rect(300, 300, 500, 200), 'PDFTronApprovalSig')
		page1 = doc.GetPage(1)
		page1.AnnotPushBack(widgetAnnotApproval)
		doc.Save(output_path + 'tiger_withApprovalField_output.pdf', SDFDoc.e_remove_unused)
	except Exception as e:
		print(e.args)
		result = False
	#################### TEST 1: certify a PDF.
	try:
		CertifyPDF(input_path + 'tiger_withApprovalField.pdf',
			'PDFTronCertificationSig',
			input_path + 'pdftron.pfx',
			'password',
			input_path + 'pdftron.bmp',
			output_path + 'tiger_withApprovalField_certified_output.pdf')
		PrintSignaturesInfo(output_path + 'tiger_withApprovalField_certified_output.pdf')
	except Exception as e:
		print(e.args)
		result = False
	#################### TEST 2: sign a PDF with a certification and an unsigned signature field in it.
	try:
		SignPDF(input_path + 'tiger_withApprovalField_certified.pdf',
			'PDFTronApprovalSig',
			input_path + 'pdftron.pfx',
			'password',
			input_path + 'signature.jpg',
			output_path + 'tiger_withApprovalField_certified_approved_output.pdf')
		PrintSignaturesInfo(output_path + 'tiger_withApprovalField_certified_approved_output.pdf')
	except Exception as e:
		print(e.args)
		result = False
	#################### TEST 3: Clear a certification from a document that is certified and has an approval signature.
	try:
		ClearSignature(input_path + 'tiger_withApprovalField_certified_approved.pdf',
			'PDFTronCertificationSig',
			output_path + 'tiger_withApprovalField_certified_approved_certcleared_output.pdf')
		PrintSignaturesInfo(output_path + 'tiger_withApprovalField_certified_approved_certcleared_output.pdf')
	except Exception as e:
		print(e.args)
		result = False

	#################### TEST 4: Verify a document's digital signatures.
	try:
		# EXPERIMENTAL. Digital signature verification is undergoing active development, but currently does not support a number of features. If we are missing a feature that is important to you, or if you have files that do not act as expected, please contact us using one of the following forms: https://www.pdftron.com/form/trial-support/ or https://www.pdftron.com/form/request/
		VerifyAllAndPrint(input_path + "tiger_withApprovalField_certified_approved.pdf", input_path + "pdftron.cer")
	except Exception as e:
		print(e.args)
		result = False
	
	#################### End of tests. ####################

	if not result:
		print("Tests FAILED!!!\n==========")
		return
	
	print("Tests successful.\n==========")

if __name__ == '__main__':
	main()
# end if __name__ == '__main__'