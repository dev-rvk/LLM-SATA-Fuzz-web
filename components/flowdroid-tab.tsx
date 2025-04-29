"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Download } from "lucide-react"
import { CodeBlock } from "@/components/code-block"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"

// Import sample data
// import flowdroidResults from "@/output/flowdroid/diva-beta/flowdroid_results.xml"

const flowdroidResults = `<?xml version="1.0" encoding="UTF-8"?>
<DataFlowResults FileFormatVersion="102" TerminationState="Success">
    <Results>
        <Result>
            <Sink
                Statement="interfaceinvoke $r3.&lt;android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)&gt;(&quot;password&quot;, $r7)"
                Method="&lt;jakhar.aseem.diva.InsecureDataStorage1Activity: void saveCredentials(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)&gt;">
                <AccessPath Value="$r7" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r6 = virtualinvoke r5.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage1Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r6" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
        <Result>
            <Sink
                Statement="virtualinvoke $r5.&lt;android.database.sqlite.SQLiteDatabase: void execSQL(java.lang.String)&gt;($r8)"
                Method="&lt;jakhar.aseem.diva.InsecureDataStorage2Activity: void saveCredentials(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;android.database.sqlite.SQLiteDatabase: void execSQL(java.lang.String)&gt;">
                <AccessPath Value="$r8" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r7 = virtualinvoke r4.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage2Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r7" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
                <Source
                    Statement="$r7 = virtualinvoke r3.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage2Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r7" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
        <Result>
            <Sink
                Statement="staticinvoke &lt;android.util.Log: int e(java.lang.String,java.lang.String)&gt;(&quot;diva-log&quot;, $r5)"
                Method="&lt;jakhar.aseem.diva.LogActivity: void checkout(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;android.util.Log: int e(java.lang.String,java.lang.String)&gt;">
                <AccessPath Value="$r5" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r4 = virtualinvoke r3.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.LogActivity: void checkout(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r4" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
        <Result>
            <Sink
                Statement="interfaceinvoke $r3.&lt;android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)&gt;($r9, $r6)"
                Method="&lt;jakhar.aseem.diva.AccessControl3Activity: void addPin(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)&gt;">
                <AccessPath Value="$r6" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r5 = virtualinvoke r4.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.AccessControl3Activity: void addPin(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r5" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
        <Result>
            <Sink
                Statement="interfaceinvoke $r3.&lt;android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)&gt;(&quot;user&quot;, $r7)"
                Method="&lt;jakhar.aseem.diva.InsecureDataStorage1Activity: void saveCredentials(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;android.content.SharedPreferences$Editor: android.content.SharedPreferences$Editor putString(java.lang.String,java.lang.String)&gt;">
                <AccessPath Value="$r7" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r6 = virtualinvoke r4.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage1Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r6" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
        <Result>
            <Sink
                Statement="virtualinvoke r4.&lt;java.io.FileWriter: void write(java.lang.String)&gt;($r8)"
                Method="&lt;jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;java.io.Writer: void write(java.lang.String)&gt;">
                <AccessPath Value="$r8" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r10 = virtualinvoke r6.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r10" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
                <Source
                    Statement="$r10 = virtualinvoke r5.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage3Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r10" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
        <Result>
            <Sink
                Statement="virtualinvoke r3.&lt;java.io.FileWriter: void write(java.lang.String)&gt;($r9)"
                Method="&lt;jakhar.aseem.diva.InsecureDataStorage4Activity: void saveCredentials(android.view.View)&gt;"
                MethodSourceSinkDefinition="&lt;java.io.Writer: void write(java.lang.String)&gt;">
                <AccessPath Value="$r9" Type="java.lang.String" TaintSubFields="true"></AccessPath>
            </Sink>
            <Sources>
                <Source
                    Statement="$r10 = virtualinvoke r6.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage4Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r10" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
                <Source
                    Statement="$r10 = virtualinvoke r5.&lt;android.widget.EditText: android.text.Editable getText()&gt;()"
                    Method="&lt;jakhar.aseem.diva.InsecureDataStorage4Activity: void saveCredentials(android.view.View)&gt;"
                    MethodSourceSinkDefinition="&lt;android.widget.EditText: android.text.Editable getText()&gt;">
                    <AccessPath Value="$r10" Type="android.text.Editable" TaintSubFields="true"></AccessPath>
                </Source>
            </Sources>
        </Result>
    </Results>
    <PerformanceData>
        <PerformanceEntry Name="TotalRuntimeSeconds" Value="1"></PerformanceEntry>
        <PerformanceEntry Name="MaxMemoryConsumption" Value="120"></PerformanceEntry>
        <PerformanceEntry Name="SourceCount" Value="24"></PerformanceEntry>
        <PerformanceEntry Name="SinkCount" Value="21"></PerformanceEntry>
    </PerformanceData>
</DataFlowResults>`
export function FlowdroidTab({ apkName }: { apkName: string }) {
  const [results, setResults] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // In a real app, you would fetch this data from your API
    // For now, we'll use the imported sample data
    setResults(flowdroidResults)
    setLoading(false)
  }, [apkName])

  if (loading) {
    return <div className="flex justify-center p-8">Loading FlowDroid analysis results...</div>
  }

  if (!results) {
    return <div className="flex justify-center p-8">No FlowDroid analysis results found.</div>
  }

  // Parse the XML to display in a more structured way
  // This is a simplified example - in a real app, you would use a proper XML parser
  const parseResults = () => {
    try {
      const parser = new DOMParser()
      const xmlDoc = parser.parseFromString(results, "text/xml")

      const resultElements = xmlDoc.getElementsByTagName("Result")
      const parsedResults = []

      for (let i = 0; i < resultElements.length; i++) {
        const result = resultElements[i]
        const sink = result.getElementsByTagName("Sink")[0]
        const sources = result.getElementsByTagName("Source")

        parsedResults.push({
          id: i,
          sink: {
            statement: sink.getAttribute("Statement"),
            method: sink.getAttribute("Method"),
            definition: sink.getAttribute("MethodSourceSinkDefinition"),
          },
          sources: Array.from(sources).map((source) => ({
            statement: source.getAttribute("Statement"),
            method: source.getAttribute("Method"),
            definition: source.getAttribute("MethodSourceSinkDefinition"),
          })),
        })
      }

      return parsedResults
    } catch (error) {
      console.error("Error parsing XML:", error)
      return []
    }
  }

  const parsedResults = parseResults()

  return (
    <div className="space-y-6 p-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">FlowDroid Analysis</h2>
          <p className="text-muted-foreground">
            FlowDroid is a data flow analysis tool. FlowDroid statically computes data flows in Android apps and Java
            programs. Its goal is to provide researchers and practitioners with a tool and library on which they can
            base their own research projects and product implementations.
          </p>
        </div>
        <Button variant="outline">
          <Download className="mr-2 h-4 w-4" />
          Download XML Report
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Data Flow Results</CardTitle>
          <CardDescription>Detected data flows from sources to sinks</CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            {parsedResults.map((result, index) => (
              <AccordionItem key={index} value={`result-${index}`}>
                <AccordionTrigger className="text-left">
                  <div className="flex-1">
                    <div className="font-medium">Flow #{index + 1}</div>
                    <div className="text-sm text-muted-foreground truncate max-w-[600px]">{result.sink.method}</div>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  <div className="space-y-4">
                    <div>
                      <h4 className="text-sm font-medium mb-1">Sink</h4>
                      <div className="space-y-2">
                        <div>
                          <span className="text-xs font-medium">Method: </span>
                          <span className="text-xs">{result.sink.method}</span>
                        </div>
                        <div>
                          <span className="text-xs font-medium">Statement: </span>
                          <span className="text-xs">{result.sink.statement}</span>
                        </div>
                        <div>
                          <span className="text-xs font-medium">Definition: </span>
                          <span className="text-xs">{result.sink.definition}</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-sm font-medium mb-1">Sources ({result.sources.length})</h4>
                      {result.sources.map((source, sourceIndex) => (
                        <div key={sourceIndex} className="border p-2 rounded-md mb-2">
                          <div className="space-y-1">
                            <div>
                              <span className="text-xs font-medium">Method: </span>
                              <span className="text-xs">{source.method}</span>
                            </div>
                            <div>
                              <span className="text-xs font-medium">Statement: </span>
                              <span className="text-xs">{source.statement}</span>
                            </div>
                            <div>
                              <span className="text-xs font-medium">Definition: </span>
                              <span className="text-xs">{source.definition}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Raw XML Report</CardTitle>
          <CardDescription>The original FlowDroid XML report</CardDescription>
        </CardHeader>
        <CardContent>
          <CodeBlock code={results} language="xml" />
        </CardContent>
      </Card>
    </div>
  )
}
