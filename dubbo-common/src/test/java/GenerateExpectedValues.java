/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.apache.dubbo.common.io.Bytes;

import java.io.File;
import java.io.IOException;
import java.util.Base64;

public class GenerateExpectedValues {
    public static void main(String[] args) throws IOException {
        // Calculate SHA3-256 for "dubbo" string
        byte[] sha3String = Bytes.getMD5("dubbo");
        String base64String = Base64.getEncoder().encodeToString(sha3String);
        System.out.println("SHA3-256 for 'dubbo': " + base64String);

        // Calculate SHA3-256 for test file
        try {
            File testFile = new File(GenerateExpectedValues.class
                    .getClassLoader()
                    .getResource("md5.testfile.txt")
                    .getFile());
            byte[] sha3File = Bytes.getMD5(testFile);
            String base64File = Base64.getEncoder().encodeToString(sha3File);
            System.out.println("SHA3-256 for test file: " + base64File);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
    }
}
