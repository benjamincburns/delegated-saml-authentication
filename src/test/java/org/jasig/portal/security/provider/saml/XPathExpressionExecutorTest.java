/**
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.jasig.portal.security.provider.saml;

import java.io.InputStream;
import java.util.Random;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.jasig.portal.util.ThreadGroupRunner;
import org.junit.Test;
import org.w3c.dom.Document;

/**
 * @author Eric Dalquist
 * @version $Revision$
 */
public class XPathExpressionExecutorTest {
    @Test
    public void doNothingTest() {
    }
    public void testXPathExpressionPool() throws Exception {
        final InputStream authRequestStream = this.getClass().getResourceAsStream("/authRequest.xml");
        final Document authRequest = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(authRequestStream);
        
        final SAMLNamespaceContext namespaceContext = new SAMLNamespaceContext();
        final XPathExpressionPool pool = new XPathExpressionPool(namespaceContext);
        
        final XPathExpressionExecutor executor = new XPathExpressionExecutor() {
            private final XPathFactory xPathFactory = XPathFactory.newInstance();
            
            @SuppressWarnings("unchecked")
            @Override
            public <T> T evaluate(String expression, Object item, QName returnType) throws XPathExpressionException {
                final XPath xPath = xPathFactory.newXPath();
                xPath.setNamespaceContext(namespaceContext);
                final XPathExpression xPathExpression = xPath.compile(expression);
                return (T)xPathExpression.evaluate(item, returnType);
            }
        };
        
        for (int index = 0; index < 20; index++) {
            TimeUnit.SECONDS.sleep(10);
            if (index % 2 == 0) {
                pool.clear();
                final long iterations = this.testXPathExpressionExecutor(pool, authRequest, 20, 30);
                System.out.println("POOLED: " +iterations + ", " +pool.getNumActive() + ", " +pool.getNumIdle());
            }
            else {
                final long iterations = this.testXPathExpressionExecutor(executor, authRequest, 20, 30);
                System.out.println("CREATE: " +iterations);
            }
        }
        
        pool.close();
    }
    
    private long testXPathExpressionExecutor(final XPathExpressionExecutor executor, final Document authRequest, int threads, int duration) throws Exception {
        final ThreadGroupRunner runner = new ThreadGroupRunner("XPathExpressionPool", true);
        
        final Random RND = new Random(0);
        final CyclicBarrier startBarrier = new CyclicBarrier(threads + 1);
        final AtomicBoolean running = new AtomicBoolean(true);
        final AtomicLong totalIterations = new AtomicLong(0);
        
        runner.addTask(threads, new Runnable() {
            @Override
            public void run() {
                try {
                    int iterations = 0;
                    
                    startBarrier.await();
                    
                    while (running.get()) {
                        switch (RND.nextInt(4)) {
                            case 0:
                                executor.evaluate("/S:Envelope/S:Header/paos:Request", authRequest, XPathConstants.NODE);
                                break;
                            case 1:
                                executor.evaluate("/S:Envelope/S:Header/ecp:RelayState", authRequest, XPathConstants.NODE);
                                break;
                            case 2:
                                executor.evaluate("/S:Envelope/S:Header/ecp:Request", authRequest, XPathConstants.NODE);
                                break;
                            case 3:
                                executor.evaluate("/S:Envelope/S:Header", authRequest, XPathConstants.NODE);
                                break;
                        }
                        
                        iterations++;
                    }
                    
                    totalIterations.addAndGet(iterations);
                    
                    startBarrier.await();
                }
                catch (Exception e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        });
        
        
        runner.start();
        startBarrier.await();
        
        TimeUnit.SECONDS.sleep(duration);
        
        running.set(false);
        
        startBarrier.await();
        
        return totalIterations.get();
    }
}
