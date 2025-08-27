
class CalendarioUtils:
    
    def obtener_dia_semana(self, numero):
        """
        Devuelve el nombre del día de la semana en español
        basado en un número del 1 (Lunes) al 7 (Domingo)
        """
        try:
            numero = int(numero)
        except (ValueError, TypeError):
            return "Error: Debe ingresar un número"
        
        dias = ["Lunes", "Martes", "Miércoles", "Jueves", "Viernes", "Sábado", "Domingo"]
        
        if 1 <= numero <= 7:
            return dias[numero]
        else:
            return f"Error: El número {numero} está fuera del rango válido (1-7)"
