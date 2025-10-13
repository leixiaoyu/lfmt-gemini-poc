import React, { useState } from 'react';
import { uploadFile } from '../../services/uploadService';

const FileUpload = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
    setMessage('');
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setMessage('Please select a file first!');
      return;
    }

    setIsLoading(true);
    setMessage('Uploading...');

    try {
      // Assumption: Auth token is stored in localStorage after login.
      // In a real app, this would be managed by a global auth context.
      const authToken = localStorage.getItem('authToken');
      if (!authToken) {
        setMessage('Authentication error. Please log in again.');
        setIsLoading(false);
        return;
      }

      const { s3Response, jobId } = await uploadFile(selectedFile, authToken);

      if (s3Response.status === 200) {
        setMessage(`File uploaded successfully! Your job ID is: ${jobId}`);
      } else {
        setMessage('Upload failed. Please try again.');
      }
    } catch (error) {
      setMessage(error.message || 'An unexpected error occurred.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <h3>Upload a Document for Translation</h3>
      <input type="file" onChange={handleFileChange} disabled={isLoading} />
      <button onClick={handleUpload} disabled={isLoading}>
        {isLoading ? 'Uploading...' : 'Upload'}
      </button>
      {message && <p>{message}</p>}
    </div>
  );
};

export default FileUpload;
