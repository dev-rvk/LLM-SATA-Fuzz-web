import { UploadForm } from "@/components/upload-form"

export default function Home() {
  return (
    <div className="container mx-auto py-10">
      <h1 className="text-4xl font-bold mb-8 text-center">Android APK Analyzer</h1>
      <div className="max-w-3xl mx-auto">
        <UploadForm />
      </div>
    </div>
  )
}
