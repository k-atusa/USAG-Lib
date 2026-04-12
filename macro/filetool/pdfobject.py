# test807 : pdfobject

from typing import List, Dict, Any
import fitz # pip install PyMuPDF

# single PDF page object
class Page:
    def __init__(self, doc: fitz.Document, page_num: int) -> None:
        self._doc: fitz.Document = fitz.open()
        self._doc.insert_pdf(doc, from_page=page_num, to_page=page_num)
        self.page: fitz.Page = self._doc[0]

    def __del__(self) -> None:
        if hasattr(self, '_doc'):
            self._doc.close()

    # rotate page by given angle (90 degree increments)
    def rotate(self, angle: int) -> None:
        self.page.set_rotation((self.page.rotation + angle) % 360)

    # get text from page
    def getText(self) -> str:
        return self.page.get_text()

    # get image from page (index int, extension str, bytes data)
    def getImages(self) -> List[List[int, str, bytes]]:
        images = [ ]
        image_list = self.page.get_images(full=True)
        for img_index, img in enumerate(image_list):
            xref: int = img[0]
            base_image: Dict[str, Any] = self._doc.extract_image(xref)
            images.append( [ img_index, base_image["ext"], base_image["image"] ] )
        return images

    # convert page to markdown ! NOT SUPPORTED !
    def toMD(self) -> str:
        return self.page.get_text("markdown")

    # convert page to HTML
    def toHTML(self) -> str:
        return self.page.get_text("html")

    # convert page to JSON
    def toJSON(self) -> str:
        return self.page.get_text("json")

    # convert page to SVG ! NOT SUPPORTED !
    def toSVG(self) -> str:
        return self.page.get_svg()

    # convert page to image with specified DPI
    def toImage(self, filename: str, dpi: int = 150) -> None:
        pix: fitz.Pixmap = self.page.get_pixmap(matrix=fitz.Matrix(dpi/72, dpi/72))
        pix.save(filename)

    # ===== inline utilities =====
    def get_document(self) -> fitz.Document:
        return self._doc
    
    def get_page(self) -> fitz.Page:
        return self.page
    
    def get_rotation(self) -> int:
        return self.page.rotation

# Load PDF
def LoadPDF(filepath: str) -> List[Page]:
    pages = [ ]
    doc = fitz.open(filepath)
    for i in range( 0, len(doc) ):
        pages.append(Page(doc, i))
    return pages

# Save PDF
def SavePDF(pages: List[Page], filepath: str) -> None:
    doc = fitz.open()
    for page in pages:
        doc.insert_pdf(page.get_document())
    doc.save(filepath, garbage=4, deflate=True)
    doc.close()