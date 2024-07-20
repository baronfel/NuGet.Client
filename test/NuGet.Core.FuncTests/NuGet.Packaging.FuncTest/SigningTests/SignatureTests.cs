// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable

#if IS_SIGNING_SUPPORTED

using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NuGet.Common;
using NuGet.Packaging.Signing;
using NuGet.Test.Utility;
using Test.Utility.Signing;
using Xunit;

namespace NuGet.Packaging.FuncTest
{
    [Collection(SigningTestCollection.Name)]
    public class SignatureTests
    {
        private readonly SigningTestFixture _testFixture;
        private readonly TestCertificate _untrustedTestCertificate;

        public SignatureTests(SigningTestFixture fixture)
        {
            _testFixture = fixture ?? throw new ArgumentNullException(nameof(fixture));
            _untrustedTestCertificate = _testFixture.UntrustedTestCertificate;
        }

        [CIOnlyFact]
        public async Task Verify_WithUntrustedSelfSignedCertificateAndNotAllowUntrusted_FailsAsync()
        {
            var settings = new SignatureVerifySettings(
                allowIllegal: false,
                allowUntrusted: false,
                allowUnknownRevocation: false,
                reportUnknownRevocation: true,
                reportUntrustedRoot: true,
                revocationMode: RevocationMode.Online);

            using (var test = await VerifyTest.CreateAsync(settings, _untrustedTestCertificate.Cert))
            {
                var result = test.PrimarySignature.Verify(
                    timestamp: null,
                    settings: settings,
                    fingerprintAlgorithm: Common.HashAlgorithmName.SHA256,
                    certificateExtraStore: test.PrimarySignature.SignedCms.Certificates);

                Assert.Equal(SignatureVerificationStatus.Disallowed, result.Status);
                Assert.Equal(1, result.Issues.Count(issue => issue.Level == LogLevel.Error));

                SigningTestUtility.AssertUntrustedRoot(result.Issues, LogLevel.Error);
            }
        }

        [CIOnlyFact]
        public async Task Verify_WithUntrustedSelfSignedCertificateAndAllowUntrusted_SucceedsAndWarnsAsync()
        {
            var settings = new SignatureVerifySettings(
                allowIllegal: false,
                allowUntrusted: true,
                allowUnknownRevocation: false,
                reportUnknownRevocation: true,
                reportUntrustedRoot: true,
                revocationMode: RevocationMode.Online);

            using (var test = await VerifyTest.CreateAsync(settings, _untrustedTestCertificate.Cert))
            {
                var result = test.PrimarySignature.Verify(
                    timestamp: null,
                    settings: settings,
                    fingerprintAlgorithm: Common.HashAlgorithmName.SHA256,
                    certificateExtraStore: test.PrimarySignature.SignedCms.Certificates);

                Assert.Equal(SignatureVerificationStatus.Valid, result.Status);
                Assert.Equal(0, result.Issues.Count(issue => issue.Level == LogLevel.Error));
                Assert.NotEqual(0, result.Issues.Count(issue => issue.Level == LogLevel.Warning));
            }
        }

        [CIOnlyFact]
        public async Task Verify_WithUntrustedSelfSignedCertificateAndAllowUntrustedAndNotReportUntrustedRoot_SucceedsAsync()
        {
            var settings = new SignatureVerifySettings(
                allowIllegal: false,
                allowUntrusted: true,
                allowUnknownRevocation: false,
                reportUnknownRevocation: true,
                reportUntrustedRoot: false,
                revocationMode: RevocationMode.Online);

            using (var test = await VerifyTest.CreateAsync(settings, _untrustedTestCertificate.Cert))
            {
                var result = test.PrimarySignature.Verify(
                    timestamp: null,
                    settings: settings,
                    fingerprintAlgorithm: Common.HashAlgorithmName.SHA256,
                    certificateExtraStore: test.PrimarySignature.SignedCms.Certificates);

                Assert.Equal(SignatureVerificationStatus.Valid, result.Status);
                Assert.Equal(0, result.Issues.Count(issue => issue.Level == LogLevel.Error));
                Assert.Equal(0, result.Issues.Count(issue => issue.Level == LogLevel.Warning));
            }
        }

        [CIOnlyFact]
        public async Task GetSigningCertificateFingerprint_WithUnsupportedHashAlgorithm_Throws()
        {
            using (var test = await VerifyTest.CreateAsync(settings: null, certificate: _untrustedTestCertificate.Cert))
            {
                Assert.Throws<ArgumentException>(() => test.PrimarySignature.GetSigningCertificateFingerprint((Common.HashAlgorithmName)99));
            }
        }

        [CIOnlyFact]
        public async Task GetSigningCertificateFingerprint_SuccessfullyHashesMultipleAlgorithms()
        {
            using (var test = await VerifyTest.CreateAsync(settings: null, certificate: _untrustedTestCertificate.Cert))
            {
                var sha256 = test.PrimarySignature.GetSigningCertificateFingerprint(Common.HashAlgorithmName.SHA256);
                var sha384 = test.PrimarySignature.GetSigningCertificateFingerprint(Common.HashAlgorithmName.SHA384);
                var sha512 = test.PrimarySignature.GetSigningCertificateFingerprint(Common.HashAlgorithmName.SHA512);

                var expectedSha256 = SignatureTestUtility.GetFingerprint(_untrustedTestCertificate.Cert, Common.HashAlgorithmName.SHA256);
                var expectedSha384 = SignatureTestUtility.GetFingerprint(_untrustedTestCertificate.Cert, Common.HashAlgorithmName.SHA384);
                var expectedSha512 = SignatureTestUtility.GetFingerprint(_untrustedTestCertificate.Cert, Common.HashAlgorithmName.SHA512);

                Assert.Equal(sha256, expectedSha256, StringComparer.Ordinal);
                Assert.Equal(sha384, expectedSha384, StringComparer.Ordinal);
                Assert.Equal(sha512, expectedSha512, StringComparer.Ordinal);
            }
        }

        [Fact]
        public async Task Timestamps_WitMultipleTimestamps_ReturnsMultipleTimestamps()
        {
            var timestampService = await _testFixture.GetDefaultTrustedTimestampServiceAsync();
            var timestampProvider = new Rfc3161TimestampProvider(timestampService.Url);
            var nupkg = new SimpleTestPackageContext();

            using (var packageStream = await nupkg.CreateAsStreamAsync())
            using (var testCertificate = new X509Certificate2(_testFixture.TrustedTestCertificate.Source.Cert))
            {
                AuthorPrimarySignature authorSignature = await SignedArchiveTestUtility.CreateAuthorSignatureForPackageAsync(
                    testCertificate,
                    packageStream,
                    timestampProvider);

                SignedCms updatedSignedCms = ModifyUnsignedAttributes(authorSignature.SignedCms, signerInfo =>
                {
                    Assert.True(signerInfo.TryGetUnsignedAttribute(new Oid(Oids.SignatureTimeStampTokenAttribute), out CryptographicAttributeObject? attribute));

                    AsnEncodedData value = attribute!.Values[0];

                    attribute.Values.Add(value);
                });

                var updatedAuthorSignature = new AuthorPrimarySignature(updatedSignedCms);

                Assert.Equal(2, updatedAuthorSignature.Timestamps.Count);
            }
        }

        private static SignedCms ModifyUnsignedAttributes(
            SignedCms signedCms,
            Action<TestSignerInfo> modify)
        {
            byte[] bytes = signedCms.Encode();
            TestSignedCms tempSignedCms = TestSignedCms.Decode(bytes);

            TestSignerInfo signerInfo = tempSignedCms.SignerInfos[0];

            modify(signerInfo);

            return tempSignedCms.Encode();
        }

        private static bool TryGetAttribute(
            CryptographicAttributeObjectCollection attributes,
            Oid oid,
            [NotNullWhen(true)]
            out CryptographicAttributeObject? attribute)
        {
            attribute = null;

            foreach (CryptographicAttributeObject attr in attributes)
            {
                if (string.Equals(attr.Oid.Value, oid.Value, StringComparison.Ordinal))
                {
                    attribute = attr;
                    return true;
                }
            }

            return false;
        }

        private sealed class VerifyTest : IDisposable
        {
            private readonly TestDirectory _directory;
            private readonly FileStream _signedPackageReadStream;

            private bool _isDisposed;

            internal SignedPackageArchive Package { get; }
            internal SignatureVerifySettings? Settings { get; }
            internal PrimarySignature PrimarySignature { get; }

            private VerifyTest(
                TestDirectory directory,
                FileStream signedPackageReadStream,
                SignedPackageArchive package,
                PrimarySignature primarySignature,
                SignatureVerifySettings? settings)
            {
                _directory = directory;
                _signedPackageReadStream = signedPackageReadStream;
                Package = package;
                PrimarySignature = primarySignature;
                Settings = settings;
            }

            public void Dispose()
            {
                if (!_isDisposed)
                {
                    Package.Dispose();
                    _signedPackageReadStream.Dispose();
                    _directory.Dispose();

                    GC.SuppressFinalize(this);

                    _isDisposed = true;
                }
            }

            internal static async Task<VerifyTest> CreateAsync(SignatureVerifySettings? settings, X509Certificate2 certificate)
            {
                using (var certificateClone = new X509Certificate2(certificate))
                {
                    var directory = TestDirectory.Create();
                    var packageContext = new SimpleTestPackageContext();
                    var unsignedPackageFile = await packageContext.CreateAsFileAsync(directory, "package.nupkg");
                    var signedPackageFile = await SignedArchiveTestUtility.SignPackageFileWithBasicSignedCmsAsync(
                        directory,
                        unsignedPackageFile,
                        certificateClone);
                    var signedPackageReadStream = signedPackageFile.OpenRead();
                    var package = new SignedPackageArchive(signedPackageReadStream, new MemoryStream());
                    var primarySignature = await package.GetPrimarySignatureAsync(CancellationToken.None);

                    return new VerifyTest(directory, signedPackageReadStream, package, primarySignature, settings);
                }
            }
        }
    }
}
#endif
