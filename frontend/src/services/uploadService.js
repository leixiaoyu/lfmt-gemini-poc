import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://localhost:3001';

/**
 * 1. Requests a pre-signed URL from the backend.
 * 2. Uploads the file directly to S3 using the pre-signed URL.
 * 
 * @param {File} file The file to upload.
 * @param {string} authToken The user's JWT for authorization.
 * @returns {Promise<object>} The response from the S3 upload.
 */
export const uploadFile = async (file, authToken) => {
  if (!file) {
    throw new Error('No file provided for upload');
  }

  try {
    // Step 1: Get a pre-signed URL from our backend API
    const apiResponse = await axios.post(`${API_BASE_URL}/uploads`,
      {
        fileName: file.name,
        fileType: file.type,
      },
      {
        headers: { Authorization: `Bearer ${authToken}` },
      }
    );

    const { uploadUrl, jobId } = apiResponse.data;

    // Step 2: Upload the file directly to S3 using the pre-signed URL
    const s3Response = await axios.put(uploadUrl, file, {
      headers: {
        'Content-Type': file.type,
      },
    });

    // Return both the S3 response and the jobId for tracking
    return { s3Response, jobId };

  } catch (error) {
    console.error('Error during file upload:', error.response ? error.response.data : error.message);
    throw error;
  }
};
