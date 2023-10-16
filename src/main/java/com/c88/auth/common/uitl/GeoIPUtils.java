package com.c88.auth.common.uitl;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;

@Slf4j
@Component
public class GeoIPUtils {

    @Value("${geolite2ip.path}")
    private String geoLite2IPPath;

    private DatabaseReader dbReader;

    @PostConstruct
    public void init() {
        try {
            URL url = new URL(geoLite2IPPath);
            dbReader = new DatabaseReader.Builder(url.openStream()).build();
            log.info("GeoLite2IP File Ready");
        } catch (IOException e) {
            log.info("取得GeoLite2IP資料庫失敗");
        }
    }


    /**
     * 取得位置資訊ByIP
     *
     * @param ip IP位置
     * @return
     * @throws IOException
     * @throws GeoIp2Exception
     */
    public CityResponse getGeoResponseByIP(String ip) throws IOException, GeoIp2Exception {
        InetAddress ipAddress = InetAddress.getByName(ip);
        return dbReader.city(ipAddress);
    }

}
