package com.wechat.pay.contrib.apache.httpclient;

import com.wechat.pay.contrib.apache.httpclient.auth.PrivateKeySigner;
import com.wechat.pay.contrib.apache.httpclient.auth.Signer;
import com.wechat.pay.contrib.apache.httpclient.util.NonceGenerator;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.security.PrivateKey;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntityBuilder;

public class UploadRequestBuilder {

  private PrivateKeySigner signer;
  private String merchantId;

  private String fileName;
  private String fileSha256;
  private InputStream inputStream;
  private org.apache.http.entity.ContentType fileContentType;

  private String meta;
  private URI uri;

  public static UploadRequestBuilder create() {
    return new UploadRequestBuilder();
  }

  public final String getSchema() {
    return "WECHATPAY2-SHA256-RSA2048";
  }

  public UploadRequestBuilder withMerchant(String merchantId, String serialNo,
      PrivateKey privateKey) {
    this.merchantId = merchantId;
    this.signer = new PrivateKeySigner(serialNo, privateKey);
    return this;
  }

  public UploadRequestBuilder withImageFile(String filePathName) throws IOException {
    File file = new File(filePathName);

    String sha256 = DigestUtils.sha256Hex(new FileInputStream(file));
    return withImage(file.getName(), sha256, new FileInputStream(file));
  }

  public UploadRequestBuilder withImage(String fileName, String fileSha256,
      InputStream inputStream) {
    this.fileName = fileName;
    this.fileSha256 = fileSha256;
    this.inputStream = inputStream;

    String mimeType = URLConnection.guessContentTypeFromName(fileName);
    if (mimeType == null) {
      // guess this is a video uploading
      this.fileContentType = ContentType.APPLICATION_OCTET_STREAM;
    } else {
      this.fileContentType = ContentType.create(mimeType);
    }
    return this;
  }

  public UploadRequestBuilder setUri(String uri) throws URISyntaxException {
    this.uri = new URIBuilder(uri).build();
    return this;
  }

  public HttpUriRequest build() {
    if (signer == null || merchantId == null) {
      throw new IllegalArgumentException("缺少身份认证信息");
    }

    if (fileName == null || fileSha256 == null || inputStream == null) {
      throw new IllegalArgumentException("缺少待上传图片文件信息");
    }

    if (uri == null) {
      throw new IllegalArgumentException("缺少上传图片接口URL");
    }

    meta = String.format("{\"filename\":\"%s\",\"sha256\":\"%s\"}", fileName, fileSha256);

    return buildRequest();
  }

  private String getToken() {
    long timestamp = System.currentTimeMillis() / 1000;
    String nonce = NonceGenerator.generateNonceStr();
    String message = String.format("POST\n%s\n%d\n%s\n%s\n",
        uri.getRawPath(), timestamp, nonce, meta);

    Signer.SignatureResult signature =
        signer.sign(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));

    String token = "mchid=\"" + merchantId + "\","
        + "nonce_str=\"" + nonce + "\","
        + "timestamp=\"" + timestamp + "\","
        + "serial_no=\"" + signature.getCertificateSerialNumber() + "\","
        + "signature=\"" + signature.getSign() + "\"";

    return getSchema() + " " + token;
  }

  private HttpUriRequest buildRequest() {

    MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
    entityBuilder.setMode(HttpMultipartMode.RFC6532)
        .addBinaryBody("file", inputStream, fileContentType, fileName)
        .addTextBody("meta", meta, org.apache.http.entity.ContentType.APPLICATION_JSON);

    return RequestBuilder.post()
        .setUri(uri)
        .setEntity(entityBuilder.build())
        .addHeader("Accept", org.apache.http.entity.ContentType.APPLICATION_JSON.toString())
        .addHeader("Authorization", getToken())
        .build();
  }
}
