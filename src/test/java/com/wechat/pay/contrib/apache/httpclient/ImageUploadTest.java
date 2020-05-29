package com.wechat.pay.contrib.apache.httpclient;

import static org.junit.Assert.assertEquals;

import com.wechat.pay.contrib.apache.httpclient.auth.AutoUpdateCertificatesVerifier;
import com.wechat.pay.contrib.apache.httpclient.auth.PrivateKeySigner;
import com.wechat.pay.contrib.apache.httpclient.auth.WechatPay2Credentials;
import com.wechat.pay.contrib.apache.httpclient.auth.WechatPay2Validator;
import com.wechat.pay.contrib.apache.httpclient.util.PemUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ImageUploadTest {

  private static String mchId = "1900009191"; // 商户号
  private static String mchSerialNo = "1DDE55AD98ED71D6EDD4A4A16996DE7B47773A8C"; // 商户证书序列号
  private static String apiV3Key = ""; // api密钥
  // 你的商户私钥
  private static String privateKey = "-----BEGIN PRIVATE KEY-----\n"
      + "-----END PRIVATE KEY-----\n";
  private CloseableHttpClient httpClient;
  private AutoUpdateCertificatesVerifier verifier;

  private PrivateKey merchantPrivateKey;

  @Before
  public void setup() throws IOException {
    merchantPrivateKey = PemUtil.loadPrivateKey(
        new ByteArrayInputStream(privateKey.getBytes("utf-8")));

    //使用自动更新的签名验证器，不需要传入证书
    verifier = new AutoUpdateCertificatesVerifier(
        new WechatPay2Credentials(mchId, new PrivateKeySigner(mchSerialNo, merchantPrivateKey)),
        apiV3Key.getBytes("utf-8"));

    httpClient = WechatPayHttpClientBuilder.create()
        .withMerchant(mchId, mchSerialNo, merchantPrivateKey)
        .withValidator(new WechatPay2Validator(verifier))
        .build();
  }

  @After
  public void after() throws IOException {
    httpClient.close();
  }

  @Test
  public void uploadImageTest() throws Exception {
    String filePath = "/your/path/wechat.97fa9274.png";

    UploadRequestBuilder requestBuilder = UploadRequestBuilder.create();
    HttpUriRequest request = requestBuilder.withImageFile(filePath)
        .setUri("https://api.mch.weixin.qq.com/v3/merchant/media/upload")
        .withMerchant(mchId, mchSerialNo, merchantPrivateKey)
        .build();

    CloseableHttpResponse response1 = httpClient.execute(request);
    assertEquals(200, response1.getStatusLine().getStatusCode());
    try {
      HttpEntity entity1 = response1.getEntity();
      // do something useful with the response body
      // and ensure it is fully consumed
      EntityUtils.consume(entity1);
    } finally {
      response1.close();
    }
  }

}
