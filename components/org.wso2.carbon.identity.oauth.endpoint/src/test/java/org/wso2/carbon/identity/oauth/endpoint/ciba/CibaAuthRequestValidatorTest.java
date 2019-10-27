package org.wso2.carbon.identity.oauth.endpoint.ciba;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.oauth.ciba.dto.AuthResponseContextDTO;
import org.wso2.carbon.identity.oauth.ciba.dto.CibaAuthRequestDTO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.text.ParseException;

import static org.powermock.api.mockito.PowerMockito.*;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class CibaAuthRequestValidatorTest {
    private static final String CLIENT_ID_VALUE = "ca19a540f544777860e44e75f605d927";
    private static final String INACTIVE_CLIENT_ID_VALUE = "inactiveId";

    @DataProvider(name = "provideClientData")
    public Object[][] provideGoodClientData() {

        AuthResponseContextDTO authResponseContextDTO = mock(AuthResponseContextDTO.class);
        CibaAuthRequestDTO cibaAuthRequestDTO = mock(CibaAuthRequestDTO.class);

        return new Object[][]{
                {"eyfvggr.fvbdvhebr.efwgttyv",null,null,CLIENT_ID_VALUE},
                {"eyfvggr.fvbdvhebr.efwgttyv",authResponseContextDTO,null,CLIENT_ID_VALUE},
                {"eyfvggr.fvbdvhebr.efwgttyv",null,cibaAuthRequestDTO,CLIENT_ID_VALUE},
                {"eyfvggr.fvbdvhebr.efwgttyv",authResponseContextDTO,cibaAuthRequestDTO,CLIENT_ID_VALUE}

        } ;
    }

    @Test(dataProvider = "provideGoodClientData", groups = "testWithConnection")
    public void testIsValidClient(String request,AuthResponseContextDTO authResponseContextDTO,
                                  CibaAuthRequestDTO cibaAuthRequestDTO,String clientIDValue){

        CibaAuthRequestValidator cibaAuthRequestValidator = mock(CibaAuthRequestValidator.class);

        try {
            assertTrue(cibaAuthRequestValidator.isValidClient(request,authResponseContextDTO,cibaAuthRequestDTO), null);
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (IdentityOAuth2Exception e) {
            e.printStackTrace();
        }


    }

}
