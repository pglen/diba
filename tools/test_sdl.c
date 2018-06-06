#include "SDL2/SDL.h" 
#include <stdio.h>

int main( int argc, char* args[] ) 
{ 
  SDL_Window     *window;

    SDL_Init(SDL_INIT_EVERYTHING);

    SDL_Event test_event;
    
    window = SDL_CreateWindow("SDL2 Window", 100, 100, 640, 480, 0); 
    while (SDL_PollEvent(&test_event)) {

    printf("event\n");
    
    switch (test_event.type) {
    
        case SDL_KEYDOWN:
        
           // printf("%d %d  ", test_event.keysim.scancode,
           //                 test_event.keysim.sym);
           printf("Keypress\n");
            fflush(stdout);

        }
    }
    
    if(window==NULL)
        {   
        printf("Could not create window: %s\n", SDL_GetError());
        return 1;
        }
     
    SDL_StartTextInput();
    int numkeys, old_key = 0, got = 0;
    
    for(int loop = 0; loop < 200; loop++)
        {
        SDL_PumpEvents();
        const Uint8 *ptr = SDL_GetKeyboardState(&numkeys);
        //printf("got kb states: %s\n", ptr); 
        
        got = 0;
        for(int loop2 = 0; loop2 < numkeys; loop2++)
            {
            if(ptr[loop2])
                {
                if(loop2 != old_key)
                    {
                    printf("%d %s  ", loop2, SDL_GetScancodeName(loop2)); 
                    fflush(stdout);
                    old_key = loop2;     
                    }
                got = 1;
                }
            }   
        if(got == 0)
            old_key = 0;        
        
        //printf("\n");
        SDL_Delay(30);
        }
    
    //SDL_DestroyWindow(window); 
   
    SDL_Quit(); 

  return 0;   
}

