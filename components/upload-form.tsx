"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Upload, FileUp } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { useToast } from "@/components/ui/use-toast"

export function UploadForm() {
  const router = useRouter()
  const { toast } = useToast()
  const [file, setFile] = useState<File | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [analysisOptions, setAnalysisOptions] = useState({
    staticAnalysis: true,
    artifactGeneration: false,
    completeFuzzing: false,
  })

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragging(false)

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0]
      if (droppedFile.name.endsWith(".apk")) {
        setFile(droppedFile)
      } else {
        toast({
          title: "Invalid file type",
          description: "Please upload an APK file",
          variant: "destructive",
        })
      }
    }
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const selectedFile = e.target.files[0]
      if (selectedFile.name.endsWith(".apk")) {
        setFile(selectedFile)
      } else {
        toast({
          title: "Invalid file type",
          description: "Please upload an APK file",
          variant: "destructive",
        })
      }
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!file) {
      toast({
        title: "No file selected",
        description: "Please select an APK file to analyze",
        variant: "destructive",
      })
      return
    }

    setIsLoading(true)

    // Simulate file upload and processing
    setTimeout(() => {
      setIsLoading(false)
      toast({
        title: "Analysis started",
        description: "Your APK is being analyzed",
      })

      // Navigate to results page (using a fixed APK name for demo)
      router.push("/analysis/diva-beta")
    }, 5000)
  }

  return (
    <Card className="w-full">
      <CardHeader>
        <CardTitle>Upload APK for Analysis</CardTitle>
        <CardDescription>Drag and drop your APK file or click to browse</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit}>
          <div
            className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors ${
              isDragging ? "border-primary bg-primary/5" : "border-gray-300 hover:border-primary"
            }`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => document.getElementById("file-upload")?.click()}
          >
            <input id="file-upload" type="file" accept=".apk" className="hidden" onChange={handleFileChange} />
            <Upload className="h-10 w-10 mx-auto mb-3 text-gray-400" />
            {file ? (
              <div>
                <p className="text-sm font-medium">{file.name}</p>
                <p className="text-xs text-gray-500">{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
              </div>
            ) : (
              <div>
                <p className="text-sm font-medium">Drop your APK file here or click to browse</p>
                <p className="text-xs text-gray-500">Only .apk files are supported</p>
              </div>
            )}
          </div>

          <div className="mt-6 space-y-4">
            <h3 className="text-sm font-medium">Analysis Options</h3>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="static-analysis"
                  checked={analysisOptions.staticAnalysis}
                  onCheckedChange={(checked) =>
                    setAnalysisOptions({ ...analysisOptions, staticAnalysis: checked as boolean })
                  }
                />
                <Label htmlFor="static-analysis">Static Analysis</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="artifact-generation"
                  checked={analysisOptions.artifactGeneration}
                  onCheckedChange={(checked) =>
                    setAnalysisOptions({ ...analysisOptions, artifactGeneration: checked as boolean })
                  }
                />
                <Label htmlFor="artifact-generation">Artifact Generation</Label>
              </div>
              <div className="flex items-center space-x-2">
                <Checkbox
                  id="complete-fuzzing"
                  checked={analysisOptions.completeFuzzing}
                  onCheckedChange={(checked) =>
                    setAnalysisOptions({ ...analysisOptions, completeFuzzing: checked as boolean })
                  }
                />
                <Label htmlFor="complete-fuzzing">Complete (with Fuzzing)</Label>
              </div>
            </div>
          </div>
        </form>
      </CardContent>
      <CardFooter>
        <Button type="submit" className="w-full" onClick={handleSubmit} disabled={!file || isLoading}>
          {isLoading ? (
            <div className="flex items-center">
              <div className="animate-spin mr-2 h-4 w-4 border-2 border-current border-t-transparent rounded-full"></div>
              Analyzing...
            </div>
          ) : (
            <div className="flex items-center">
              <FileUp className="mr-2 h-4 w-4" />
              Analyze APK
            </div>
          )}
        </Button>
      </CardFooter>
    </Card>
  )
}
