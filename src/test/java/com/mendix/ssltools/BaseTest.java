package com.mendix.ssltools;

public class BaseTest {

    public static String TLSCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGIDCCBQigAwIBAgISAwWmYXsDbTUZPcOyNG/I7roNMA0GCSqGSIb3DQEBCwUA\n" +
            "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n" +
            "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNjA1MjMxMjQ2MDBaFw0x\n" +
            "NjA4MjExMjQ2MDBaMCkxJzAlBgNVBAMTHmhpZXJuaWV0cG9lcGVuLnRlc3QubWVu\n" +
            "ZGl4LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMBcW5zeKqQ8\n" +
            "dgc37c5o1K5WyF/PL7BhkV1nNFuunZwsFgQGtU0CYFwxKXBSQHQinSATO3xi8zt7\n" +
            "FVdpwW6lS/2jIKIVECEGYac5x04CjXMAD7ODx3hNotyrDymZRMutpeU2+MDz8SIC\n" +
            "zEW9w1hwds9omXhz9ERx/o7PMBM4WGYO1dWrNBDf3tdOwz2Xa9QdDtK3Ad1jyZnt\n" +
            "21C+oQeySnAnkD5z8uBhwTNAYNbfVts6HIPlW6VaLmFXWplPBlzgIMqaQl4V0vQd\n" +
            "5H49wjBomzXLBBK21bYeQQ5r9zcB7YQONGuQLOrLiQ8oZP8zziYKmkRe/ZX1aCSg\n" +
            "63AU2l+2lvqBQbOZjn4ZalgkfQKHwzutMDlXA81Aifwp7fhWtsNaCo8S4bwA2lXm\n" +
            "G/lHZy8K7tsvturLMG8X7bzVp/Q//+gslaZS8Sih/NFd/prr5ptr87Pe+3Yx/t37\n" +
            "lUbfHYTJcTTFanl/Zp432UddqwEgNZ8+PTi5Wy8/gp2+hS1jhfClqSTVmSYZIcnh\n" +
            "wFM93GDHQZkFfpBozeBoR/ymqOUTc4cYyY+rN3r33Jum4bP3a43PmNXMvKcG0OkC\n" +
            "gZvgcWgguf/mMxpxXBCcMseR9Dowi0m8gnap54Qu1nKzvBYpS3FXozzHUTJpx+ky\n" +
            "P/VpdT7mrAJuzq2wMKeuASw8CLNMs2z9AgMBAAGjggIfMIICGzAOBgNVHQ8BAf8E\n" +
            "BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQC\n" +
            "MAAwHQYDVR0OBBYEFHOAqc/ylWzOL15IDbthTuiQff5UMB8GA1UdIwQYMBaAFKhK\n" +
            "amMEfd265tE5t6ZFZe/zqOyhMHAGCCsGAQUFBwEBBGQwYjAvBggrBgEFBQcwAYYj\n" +
            "aHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8wLwYIKwYBBQUHMAKG\n" +
            "I2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMCkGA1UdEQQiMCCC\n" +
            "HmhpZXJuaWV0cG9lcGVuLnRlc3QubWVuZGl4LmNvbTCB/gYDVR0gBIH2MIHzMAgG\n" +
            "BmeBDAECATCB5gYLKwYBBAGC3xMBAQEwgdYwJgYIKwYBBQUHAgEWGmh0dHA6Ly9j\n" +
            "cHMubGV0c2VuY3J5cHQub3JnMIGrBggrBgEFBQcCAjCBngyBm1RoaXMgQ2VydGlm\n" +
            "aWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVkIHVwb24gYnkgUmVseWluZyBQYXJ0aWVz\n" +
            "IGFuZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9s\n" +
            "aWN5IGZvdW5kIGF0IGh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL3JlcG9zaXRvcnkv\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQBFW6mKmjwQe68f/1RNfyLkOS7ux8pYWfvajtdX\n" +
            "QsBBLPdQ2/zXrIu5b+I2GaGyy+DRmgzR2bMENuYK7mxkoFIZUyEUmiDJUgMiMAkE\n" +
            "36L5zcV76WcGD+mPSvaXXjWXsBvTfMteupS0wVn7Ytbln21NyGKjyaVB38p9bBKk\n" +
            "krLq1iTWCycpxHyQ2CxXJR4+YByfT30Nk55vgZl78j+GVzeq3vTa08H0uq0CmKMd\n" +
            "hdFhmYUw3MSA4M+enZowfSUaEo8eVpd2h0dkuQycIFTHN5a4Nz7WuIWyCIq9vMlK\n" +
            "xZtRWxBG6lE+VAkbWdrt5FLPIO1pRbHP7ptJmgRvJ25pGZva\n" +
            "-----END CERTIFICATE-----";

    public static String PrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIJKQIBAAKCAgEAwFxbnN4qpDx2BzftzmjUrlbIX88vsGGRXWc0W66dnCwWBAa1\n" +
            "TQJgXDEpcFJAdCKdIBM7fGLzO3sVV2nBbqVL/aMgohUQIQZhpznHTgKNcwAPs4PH\n" +
            "eE2i3KsPKZlEy62l5Tb4wPPxIgLMRb3DWHB2z2iZeHP0RHH+js8wEzhYZg7V1as0\n" +
            "EN/e107DPZdr1B0O0rcB3WPJme3bUL6hB7JKcCeQPnPy4GHBM0Bg1t9W2zocg+Vb\n" +
            "pVouYVdamU8GXOAgyppCXhXS9B3kfj3CMGibNcsEErbVth5BDmv3NwHthA40a5As\n" +
            "6suJDyhk/zPOJgqaRF79lfVoJKDrcBTaX7aW+oFBs5mOfhlqWCR9AofDO60wOVcD\n" +
            "zUCJ/Cnt+Fa2w1oKjxLhvADaVeYb+UdnLwru2y+26sswbxftvNWn9D//6CyVplLx\n" +
            "KKH80V3+muvmm2vzs977djH+3fuVRt8dhMlxNMVqeX9mnjfZR12rASA1nz49OLlb\n" +
            "Lz+Cnb6FLWOF8KWpJNWZJhkhyeHAUz3cYMdBmQV+kGjN4GhH/Kao5RNzhxjJj6s3\n" +
            "evfcm6bhs/drjc+Y1cy8pwbQ6QKBm+BxaCC5/+YzGnFcEJwyx5H0OjCLSbyCdqnn\n" +
            "hC7WcrO8FilLcVejPMdRMmnH6TI/9Wl1PuasAm7OrbAwp64BLDwIs0yzbP0CAwEA\n" +
            "AQKCAgAc/k64qCvZMVvA3sczM03LMT1mY34Wob4dS+7yWrFa1rJCzRgKkW8gtjA+\n" +
            "w8b/OjBgo0V2DBwJPRYMZN5I5RU9F5dVlsMllyak4+qMcYoMaVf0gMpR8bG4fPf+\n" +
            "FyHtaTD2CYEY5CvWKoHLiTymWd0uid+H7kJFBsGNmODwJK/+QgItAG8KlBOsdCyt\n" +
            "XeNcxzxyui7HxcCfOOCznOf8lvztRqlRIHzdIR7TsMJn4KXgyTN/FdToaV1QQrBf\n" +
            "JzAYU5fdsb6LG9L+BHtqI7jfPwUV6JGmmHRBzPGVUOSkH+BC5Tk1dTev9BmmdToz\n" +
            "1QUfar2xzHeAYMrfqnmSHTKE9qpuuFcxhijVfVxAeC9L6YQxeo04RTquvu/ZdNf6\n" +
            "pfSrha92ue/434mDRFFFu6EHtKnKjo66GilUDBI/VV+adBr9Dc4cuPvyShxxioTI\n" +
            "pcU899ZPYl4TnhaO1/re2ZUJhuUNXiEDzzRZNyOMT5l/bFuXMHdm+CN9QBUyetnF\n" +
            "FIdN9VQINWcjxMCesVUFLYgTJlx0JROVsmYpoJTijoWan3p+fOCvE63F886jRixR\n" +
            "8swMFypI/o95dw9XVRbGWtk40nLmrGr3U89fBNjUICxCJLs/z5iHtmepBvhK20V5\n" +
            "IqBQiV/Zytqv7EARjXiS0Z8YCAcyjdIBsMa9sB1ZOc/5PVtFgQKCAQEA898/RgMj\n" +
            "iQa2Dbgxrq6m8/s6D4g3XRGAoeb5K3vcSpyIRPriI4zXS39wHJ51oGJwiI5c3wmX\n" +
            "xRRttVaEH+pXXd+KClmAdjFWIpsWup/pnoQ9Wb6Aeb+clEQdEJEmO2XzCWrG/Cc3\n" +
            "7fSOyOXfiOoVGJT7QZeqMZKzLLjODwgf9VXXzmnMECx0aysYupxY2tQTRjmM1X2O\n" +
            "Ynps0iVHok+YiAMDvJMT7EuimUU6W8AHvV7nCrCkU6lQFuxYxuR6uwjKHUa1k06F\n" +
            "LFeU4olDnsJYxoG8oPt9sXjqKH/0i8YVGC8KiUn7OOdL/gEskBc1hQdIh6BH61Kl\n" +
            "8XINbr96j8mWDQKCAQEAye1RGNxgd8aIoMCqraRj04UOjuIPB9dt4aj8bGapoTVq\n" +
            "O/m/s6vcRPhu6qXOd9SjqNXqoKWQ2OEz+dWQKk9G37vm626tJT62tel5CL8HtnDH\n" +
            "acfsOuly47jbvE5mpHjtX11O4p1242at0nSb60n/FFRxGtEDEeqqqLOmb7GIAN+E\n" +
            "+EYt7a84E1TW7a5qjJmeYTNsObMCLnpkq02guy4KQqJD4DX1E6MIyghIfm/KMwbF\n" +
            "HV0GG15fvO5gV8/nPNsCfQzZAOsAulfhpTJn5rO6TshnIXR2e6wq5OV1AtDMUUYw\n" +
            "0xXqdGpJMh3qU+a6QZRHveh9BX2ws05Y0vTc9c/msQKCAQEAqaWFiJiqYaoPfx/B\n" +
            "P/kzHsqHK0Lg8Jc6WmYos30oU6bsjL/SDFTveA+g1+fLf9S63+PY6zbrIygA4YLb\n" +
            "yq/kMuNMTcLRQGc1ukEU4KJZi/IGE6YYDZmjvOhdJ6cxZ2SWWtiyr7pAiAH2Sf7P\n" +
            "L5lXL5CD8K8mr/GTPusYPRCz2qDqzSZ/1Eh4fAyw2S/mB+Q7vEBQnjsHj64GgXF5\n" +
            "kYm5W/Rs5wORenFrHSAxZp4BRFT+eEtFJQXFNw0W/NT4I6ALqa4EpgKbVatfYO+H\n" +
            "4KrlwsGBjKMmXwz0J1RLs+gJyJcAx1x1rLIKBRqf+2SJ0I6uf9qZ7TPDSGDEw2Pk\n" +
            "SJ49CQKCAQAf0ZSA3WEaHp+y7Qk4GXpdf07+9uI1cx3ufClij37VV0xpLP6nOkKY\n" +
            "X6liskPpoAk19pdlPxGnCz2cdamk8R8S7FID8Um5X7t8yNB4r1lwxy61HXq9AcJH\n" +
            "3f5KGvSToDaPW22tyfBM/wYO7q8PEXbvZir4dc0NCrRfpwdn/EqZEJ+sW6qrFHw6\n" +
            "l5jSlTRW+XH6kRbRtMJ4PnMUh0P3mtalD1qwvu/ia0NcSpfZzJXJGpz+9oSa1XEy\n" +
            "nUFzNOCUN1KaD+c1/NH9ixGUbW/v64xFE9EkdWyiKkwMC5g3nF1FxVC2QnLSa1kj\n" +
            "W5FsLSRWZx4y76qbreWlK4hVnZ4f4eXRAoIBAQDrJ0kWS2tL8yjnJpwr/9y6uNxO\n" +
            "EwDCWWf/FkO/o1ajKf2CfZ67TBWMT5/qL8zP3DNj+WqQfg84pQ3juPhtv/aqx4xL\n" +
            "/POYEdHNYbGDbCWA31YZfOgD0dnrlh/lrzssf6xyDJSz0AZLTiTJrdHAIItSg+Q8\n" +
            "iPakjTklONORBRj7WPmKa+kW574JxQV9Jrh63PXMjvPEq/G54JIv7mX5vWXNajK7\n" +
            "qNJ7NNRQ0LtJOfQMvJgqSFcINVFnK/jKJwOwIo0P9gDHlP8bT18ere+0qKAalrXR\n" +
            "jZzCQ8K/4Z3Bc0a4+OlPolvH3OBLqAUmice9YGKe4Uhw5S2kW5Ltw/bkCNVe\n" +
            "-----END RSA PRIVATE KEY-----";

    public static String TLSCertificateChain = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n" +
            "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
            "DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n" +
            "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n" +
            "Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n" +
            "rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n" +
            "OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n" +
            "xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n" +
            "7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n" +
            "aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n" +
            "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n" +
            "SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n" +
            "ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n" +
            "AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n" +
            "R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n" +
            "JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n" +
            "Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n" +
            "-----END CERTIFICATE-----\n"+
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/\n" +
            "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
            "DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow\n" +
            "SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT\n" +
            "GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF\n" +
            "q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8\n" +
            "SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0\n" +
            "Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA\n" +
            "a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj\n" +
            "/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T\n" +
            "AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG\n" +
            "CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv\n" +
            "bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k\n" +
            "c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw\n" +
            "VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC\n" +
            "ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz\n" +
            "MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu\n" +
            "Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF\n" +
            "AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo\n" +
            "uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/\n" +
            "wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu\n" +
            "X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG\n" +
            "PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6\n" +
            "KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\n" +
            "-----END CERTIFICATE-----";

    public static String unorderedTLSCertificateChain = "-----BEGIN CERTIFICATE-----\n" +
            "MIIEqDCCA5CgAwIBAgIRAJgT9HUT5XULQ+dDHpceRL0wDQYJKoZIhvcNAQELBQAw\n" +
            "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n" +
            "Ew5EU1QgUm9vdCBDQSBYMzAeFw0xNTEwMTkyMjMzMzZaFw0yMDEwMTkyMjMzMzZa\n" +
            "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n" +
            "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBAJzTDPBa5S5Ht3JdN4OzaGMw6tc1Jhkl4b2+NfFwki+3uEtB\n" +
            "BaupnjUIWOyxKsRohwuj43Xk5vOnYnG6eYFgH9eRmp/z0HhncchpDpWRz/7mmelg\n" +
            "PEjMfspNdxIknUcbWuu57B43ABycrHunBerOSuu9QeU2mLnL/W08lmjfIypCkAyG\n" +
            "dGfIf6WauFJhFBM/ZemCh8vb+g5W9oaJ84U/l4avsNwa72sNlRZ9xCugZbKZBDZ1\n" +
            "gGusSvMbkEl4L6KWTyogJSkExnTA0DHNjzE4lRa6qDO4Q/GxH8Mwf6J5MRM9LTb4\n" +
            "4/zyM2q5OTHFr8SNDR1kFjOq+oQpttQLwNh9w5MCAwEAAaOCAZIwggGOMBIGA1Ud\n" +
            "EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMH8GCCsGAQUFBwEBBHMwcTAy\n" +
            "BggrBgEFBQcwAYYmaHR0cDovL2lzcmcudHJ1c3RpZC5vY3NwLmlkZW50cnVzdC5j\n" +
            "b20wOwYIKwYBBQUHMAKGL2h0dHA6Ly9hcHBzLmlkZW50cnVzdC5jb20vcm9vdHMv\n" +
            "ZHN0cm9vdGNheDMucDdjMB8GA1UdIwQYMBaAFMSnsaR7LHH62+FLkHX/xBVghYkQ\n" +
            "MFQGA1UdIARNMEswCAYGZ4EMAQIBMD8GCysGAQQBgt8TAQEBMDAwLgYIKwYBBQUH\n" +
            "AgEWImh0dHA6Ly9jcHMucm9vdC14MS5sZXRzZW5jcnlwdC5vcmcwPAYDVR0fBDUw\n" +
            "MzAxoC+gLYYraHR0cDovL2NybC5pZGVudHJ1c3QuY29tL0RTVFJPT1RDQVgzQ1JM\n" +
            "LmNybDATBgNVHR4EDDAKoQgwBoIELm1pbDAdBgNVHQ4EFgQUqEpqYwR93brm0Tm3\n" +
            "pkVl7/Oo7KEwDQYJKoZIhvcNAQELBQADggEBANHIIkus7+MJiZZQsY14cCoBG1hd\n" +
            "v0J20/FyWo5ppnfjL78S2k4s2GLRJ7iD9ZDKErndvbNFGcsW+9kKK/TnY21hp4Dd\n" +
            "ITv8S9ZYQ7oaoqs7HwhEMY9sibED4aXw09xrJZTC9zK1uIfW6t5dHQjuOWv+HHoW\n" +
            "ZnupyxpsEUlEaFb+/SCI4KCSBdAsYxAcsHYI5xxEI4LutHp6s3OT2FuO90WfdsIk\n" +
            "6q78OMSdn875bNjdBYAqxUp2/LEIHfDBkLoQz0hFJmwAbYahqKaLn73PAAm1X2kj\n" +
            "f1w8DdnkabOLGeOVcj9LQ+s67vBykx4anTjURkbqZslUEUsn2k5xeua2zUk=\n" +
            "-----END CERTIFICATE-----\n" +
            "-----BEGIN CERTIFICATE-----\n" +
            "MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\n" +
            "MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\n" +
            "DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\n" +
            "PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\n" +
            "Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\n" +
            "rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\n" +
            "OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\n" +
            "xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\n" +
            "7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\n" +
            "aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\n" +
            "HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\n" +
            "SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\n" +
            "ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\n" +
            "AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\n" +
            "R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\n" +
            "JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\n" +
            "Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\n" +
            "-----END CERTIFICATE-----";

    public static String TLSCertificateChainWithTrailingNewline = TLSCertificateChain + "\n";

    public static String invalidTLSCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGIDCCBQigAwIBAgISAwWmYXsDbTUZPcOyNG/I7roNMA0GCSqGSIb3DQEBCwUA\n" +
            "MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\n" +
            "ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNjA1MjMxMjQ2MDBaFw0x\n" +
            "NjA4MjExMjQ2MDBaMCkxJzAlBgNVBAMTHmhpZXJuaWV0cG9lcGVuLnRlc3QubWVu\n" +
            "ZGl4LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMBcW5zeKqQ8\n" +
            "dgc37c5o1K5WyF/PL7BhkV1nNFuunZwsFgQGtU0CYFwxKXBSQHQinSATO3xi8zt7\n" +
            "FVdpwW6lS/2jIKIVECEGYac5x04CjXMAD7ODx3hNotyrDymZRMutpeU2+MDz8SIC\n" +
            "zEW9w1hwds9omXhz9ERx/o7PMBM4WGYO1dWrNBDf3tdOwz2Xa9QdDtK3Ad1jyZnt\n" +
            "21C+oQeySnAnkD5z8uBhwTNAYNbfVts6HIPlW6VaLmFXWplPBlzgIMqaQl4V0vQd\n" +
            "5H49wjBomzXLBBK21bYeQQ5r9zcB7YQONGuQLOrLiQ8oZP8zziYKmkRe/ZX1aCSg\n" +
            "63AU2l+2lvqBQbOZjn4ZalgkfQKHwzutMDlXA81Aifwp7fhWtsNaCo8S4bwA2lXm\n" +
            "wFM93GDHQZkFfpBozeBoR/ymqOUTc4cYyY+rN3r33Jum4bP3a43PmNXMvKcG0OkC\n" +
            "gZvgcWgguf/mMxpxXBCcMseR9Dowi0m8gnap54Qu1nKzvBYpS3FXozzHUTJpx+ky\n" +
            "P/VpdT7mrAJuzq2wMKeuASw8CLNMs2z9AgMBAAGjggIfMIICGzAOBgNVHQ8BAf8E\n" +
            "BAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQC\n" +
            "MAAwHQYDVR0OBBYEFHOAqc/ylWzOL15IDbthTuiQff5UMB8GA1UdIwQYMBaAFKhK\n" +
            "amMEfd265tE5t6ZFZe/zqOyhMHAGCCsGAQUFBwEBBGQwYjAvBggrBgEFBQcwAYYj\n" +
            "aHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8wLwYIKwYBBQUHMAKG\n" +
            "I2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMCkGA1UdEQQiMCCC\n" +
            "HmhpZXJuaWV0cG9lcGVuLnRlc3QubWVuZGl4LmNvbTCB/gYDVR0gBIH2MIHzMAgG\n" +
            "BmeBDAECATCB5gYLKwYBBAGC3xMBAQEwgdYwJgYIKwYBBQUHAgEWGmh0dHA6Ly9j\n" +
            "cHMubGV0c2VuY3J5cHQub3JnMIGrBggrBgEFBQcCAjCBngyBm1RoaXMgQ2VydGlm\n" +
            "IGFuZCBvbmx5IGluIGFjY29yZGFuY2Ugd2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9s\n" +
            "aWN5IGZvdW5kIGF0IGh0dHBzOi8vbGV0c2VuY3J5cHQub3JnL3JlcG9zaXRvcnkv\n" +
            "MA0GCSqGSIb3DQEBCwUAA4IBAQBFW6mKmjwQe68f/1RNfyLkOS7ux8pYWfvajtdX\n" +
            "QsBBLPdQ2/zXrIu5b+I2GaGyy+DRmgzR2bMENuYK7mxkoFIZUyEUmiDJUgMiMAkE\n" +
            "krLq1iTWCycpxHyQ2CxXJR4+YByfT30Nk55vgZl78j+GVzeq3vTa08H0uq0CmKMd\n" +
            "hdFhmYUw3MSA4M+enZowfSUaEo8eVpd2h0dkuQycIFTHN5a4Nz7WuIWyCIq9vMlK\n" +
            "xZtRWxBG6lE+VAkbWdrt5FLPIO1pRbHP7ptJmgRvJ25pGZva\n" +
            "-----END CERTIFICATE-----";

    public static String invalidPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIJKQIBAAKCAgEAwFxbnN4qpDx2BzftzmjUrlbIX88vsGGRXWc0W66dnCwWBAa1\n" +
            "TQJgXDEpcFJAdCKdIBM7fGLzO3sVV2nBbqVL/aMgohUQIQZhpznHTgKNcwAPs4PH\n" +
            "eE2i3KsPKZlEy62l5Tb4wPPxIgLMRb3DWHB2z2iZeHP0RHH+js8wEzhYZg7V1as0\n" +
            "EN/e107DPZdr1B0O0rcB3WPJme3bUL6hB7JKcCeQPnPy4GHBM0Bg1t9W2zocg+Vb\n" +
            "pVouYVdamU8GXOAgyppCXhXS9B3kfj3CMGibNcsEErbVth5BDmv3NwHthA40a5As\n" +
            "6suJDyhk/zPOJgqaRF79lfVoJKDrcBTaX7aW+oFBs5mOfhlqWCR9AofDO60wOVcD\n" +
            "zUCJ/Cnt+Fa2w1oKjxLhvADaVeYb+UdnLwru2y+26sswbxftvNWn9D//6CyVplLx\n" +
            "KKH80V3+muvmm2vzs977djH+3fuVRt8dhMlxNMVqeX9mnjfZR12rASA1nz49OLlb\n" +
            "Lz+Cnb6FLWOF8KWpJNWZJhkhyeHAUz3cYMdBmQV+kGjN4GhH/Kao5RNzhxjJj6s3\n" +
            "evfcm6bhs/drjc+Y1cy8pwbQ6QKBm+BxaCC5/+YzGnFcEJwyx5H0OjCLSbyCdqnn\n" +
            "hC7WcrO8FilLcVejPMdRMmnH6TI/9Wl1PuasAm7OrbAwp64BLDwIs0yzbP0CAwEA\n" +
            "AQKCAgAc/k64qCvZMVvA3sczM03LMT1mY34Wob4dS+7yWrFa1rJCzRgKkW8gtjA+\n" +
            "w8b/OjBgo0V2DBwJPRYMZN5I5RU9F5dVlsMllyak4+qMcYoMaVf0gMpR8bG4fPf+\n" +
            "FyHtaTD2CYEY5CvWKoHLiTymWd0uid+H7kJFBsGNmODwJK/+QgItAG8KlBOsdCyt\n" +
            "XeNcxzxyui7HxcCfOOCznOf8lvztRqlRIHzdIR7TsMJn4KXgyTN/FdToaV1QQrBf\n" +
            "JzAYU5fdsb6LG9L+BHtqI7jfPwUV6JGmmHRBzPGVUOSkH+BC5Tk1dTev9BmmdToz\n" +
            "1QUfar2xzHeAYMrfqnmSHTKE9qpuuFcxhijVfVxAeC9L6YQxeo04RTquvu/ZdNf6\n" +
            "pfSrha92ue/434mDRFFFu6EHtKnKjo66GilUDBI/VV+adBr9Dc4cuPvyShxxioTI\n" +
            "pcU899ZPYl4TnhaO1/re2ZUJhuUNXiEDzzRZNyOMT5l/bFuXMHdm+CN9QBUyetnF\n" +
            "FIdN9VQINWcjxMCesVUFLYgTJlx0JROVsmYpoJTijoWan3p+fOCvE63F886jRixR\n" +
            "P/kzHsqHK0Lg8Jc6WmYos30oU6bsjL/SDFTveA+g1+fLf9S63+PY6zbrIygA4YLb\n" +
            "yq/kMuNMTcLRQGc1ukEU4KJZi/IGE6YYDZmjvOhdJ6cxZ2SWWtiyr7pAiAH2Sf7P\n" +
            "L5lXL5CD8K8mr/GTPusYPRCz2qDqzSZ/1Eh4fAyw2S/mB+Q7vEBQnjsHj64GgXF5\n" +
            "kYm5W/Rs5wORenFrHSAxZp4BRFT+eEtFJQXFNw0W/NT4I6ALqa4EpgKbVatfYO+H\n" +
            "4KrlwsGBjKMmXwz0J1RLs+gJyJcAx1x1rLIKBRqf+2SJ0I6uf9qZ7TPDSGDEw2Pk\n" +
            "SJ49CQKCAQAf0ZSA3WEaHp+y7Qk4GXpdf07+9uI1cx3ufClij37VV0xpLP6nOkKY\n" +
            "X6liskPpoAk19pdlPxGnCz2cdamk8R8S7FID8Um5X7t8yNB4r1lwxy61HXq9AcJH\n" +
            "3f5KGvSToDaPW22tyfBM/wYO7q8PEXbvZir4dc0NCrRfpwdn/EqZEJ+sW6qrFHw6\n" +
            "l5jSlTRW+XH6kRbRtMJ4PnMUh0P3mtalD1qwvu/ia0NcSpfZzJXJGpz+9oSa1XEy\n" +
            "nUFzNOCUN1KaD+c1/NH9ixGUbW/v64xFE9EkdWyiKkwMC5g3nF1FxVC2QnLSa1kj\n" +
            "W5FsLSRWZx4y76qbreWlK4hVnZ4f4eXRAoIBAQDrJ0kWS2tL8yjnJpwr/9y6uNxO\n" +
            "EwDCWWf/FkO/o1ajKf2CfZ67TBWMT5/qL8zP3DNj+WqQfg84pQ3juPhtv/aqx4xL\n" +
            "/POYEdHNYbGDbCWA31YZfOgD0dnrlh/lrzssf6xyDJSz0AZLTiTJrdHAIItSg+Q8\n" +
            "iPakjTklONORBRj7WPmKa+kW574JxQV9Jrh63PXMjvPEq/G54JIv7mX5vWXNajK7\n" +
            "qNJ7NNRQ0LtJOfQMvJgqSFcINVFnK/jKJwOwIo0P9gDHlP8bT18ere+0qKAalrXR\n" +
            "jZzCQ8K/4Z3Bc0a4+OlPolvH3OBLqAUmice9YGKe4Uhw5S2kW5Ltw/bkCNVe\n" +
            "-----END RSA PRIVATE KEY-----";

    public static String CertificateRequest = "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIEwjCCAqoCAQAwfTELMAkGA1UEBhMCTkwxFTATBgNVBAgTDFp1aWQtSG9sbGFu\n" +
            "ZDESMBAGA1UEBxMJUm90dGVyZGFtMQ8wDQYDVQQKEwZNZW5kaXgxCTAHBgNVBAsT\n" +
            "ADEnMCUGA1UEAxMeaGllcm5pZXRwb2VwZW4udGVzdC5tZW5kaXguY29tMIICIjAN\n" +
            "BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwFxbnN4qpDx2BzftzmjUrlbIX88v\n" +
            "sGGRXWc0W66dnCwWBAa1TQJgXDEpcFJAdCKdIBM7fGLzO3sVV2nBbqVL/aMgohUQ\n" +
            "IQZhpznHTgKNcwAPs4PHeE2i3KsPKZlEy62l5Tb4wPPxIgLMRb3DWHB2z2iZeHP0\n" +
            "RHH+js8wEzhYZg7V1as0EN/e107DPZdr1B0O0rcB3WPJme3bUL6hB7JKcCeQPnPy\n" +
            "4GHBM0Bg1t9W2zocg+VbpVouYVdamU8GXOAgyppCXhXS9B3kfj3CMGibNcsEErbV\n" +
            "th5BDmv3NwHthA40a5As6suJDyhk/zPOJgqaRF79lfVoJKDrcBTaX7aW+oFBs5mO\n" +
            "fhlqWCR9AofDO60wOVcDzUCJ/Cnt+Fa2w1oKjxLhvADaVeYb+UdnLwru2y+26ssw\n" +
            "bxftvNWn9D//6CyVplLxKKH80V3+muvmm2vzs977djH+3fuVRt8dhMlxNMVqeX9m\n" +
            "njfZR12rASA1nz49OLlbLz+Cnb6FLWOF8KWpJNWZJhkhyeHAUz3cYMdBmQV+kGjN\n" +
            "4GhH/Kao5RNzhxjJj6s3evfcm6bhs/drjc+Y1cy8pwbQ6QKBm+BxaCC5/+YzGnFc\n" +
            "EJwyx5H0OjCLSbyCdqnnhC7WcrO8FilLcVejPMdRMmnH6TI/9Wl1PuasAm7OrbAw\n" +
            "p64BLDwIs0yzbP0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4ICAQCNCMUTxE75kNO0\n" +
            "HvXXHTW8Ym9CTSOe6RcTxqV2N/DbOVUUlIzum+fkx0DqKNIxR5pU2H1HI0sSr4Zy\n" +
            "vD5TLuCWXN7OSv4k/Gt4gAJDRu/+Js+EhZV8J/9UdsBLst/OezDqsvXjt7XqunHD\n" +
            "w3Bvv1wYMJh3RpyxyqPAdrDWc8thoZuVj5qaJZNcndzbWItv6F0/u2lj4CVH6Pmx\n" +
            "Beo+pVwc4rQ22TTvVmUOqZ96LLO1uWu3bFdclxkCHXmy5+rHdhzOjWq1qOZNOJ9D\n" +
            "YKhkp+Yx7Y9ihOJTq4Crvd7jTQD9zmQnu2gv4NLfzIDsVMDiPxQM7z0u1jxXHhAc\n" +
            "xr3r9LZR+vLSUCOtIYghJ1ve0THFeWgO3uZknEj13nUAD3M4A4lq8wqjy6VZVKZL\n" +
            "DgSOh108WJmbdI/XyAfNKGaG0HcjfSbnm/bj7Qq3C17l+w+wPaYT0BjfQKmUKPOI\n" +
            "myoROaNDoypSB01G+Y1jWYaWMP+godcWboGTOlil7fI9WkrKahoqNmF7n9cak3zP\n" +
            "8nbF25Tso0Ww+fi4E4bY6kKyIVrk7z+CeFszAzcvPdvoG8prCsbeLdXXvHUjC9o2\n" +
            "R/4daB1xNXLRNhNAh9DM3GW1aDwhpQaea2gw/ekaWgNFyi1dWOWOAyum5IsFAywV\n" +
            "sJVAboY8AH2tEUF8NEEkc+7hrK1Vog==\n" +
            "-----END CERTIFICATE REQUEST-----";
}
